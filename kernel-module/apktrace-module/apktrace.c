/*
 * apktrace.c — Kernel module for Android app behavioral tracing.
 *
 * Hooks into syscall entry, binder transactions, process lifecycle,
 * and network operations. Filters by UID (= Android package).
 *
 * Exposes /proc/apktrace for userspace reads (JSON lines).
 * Controlled via /proc/apktrace_ctl for adding/removing traced UIDs.
 *
 * Usage:
 *   insmod apktrace.ko
 *   echo "+10123" > /proc/apktrace_ctl    # trace UID 10123
 *   cat /proc/apktrace                    # read events
 *   echo "-10123" > /proc/apktrace_ctl    # stop tracing UID 10123
 *   rmmod apktrace
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/tracepoint.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/circ_buf.h>
#include <linux/wait.h>
#include <linux/poll.h>

#include <trace/events/syscalls.h>
#include <trace/events/sched.h>
#include <trace/events/signal.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("apk-research");
MODULE_DESCRIPTION("Android app behavioral tracing via syscall/binder/net hooks");

/* ── Configuration ──────────────────────────────────────────────── */

#define APKTRACE_RING_SIZE   (1 << 20)  /* 1M entries (power of 2 for circ_buf) */
#define APKTRACE_MAX_UIDS    256
#define APKTRACE_EVENT_SIZE  256        /* max bytes per JSON event line */

/* ── Event ring buffer ──────────────────────────────────────────── */

struct apktrace_event {
    char data[APKTRACE_EVENT_SIZE];
    int len;
};

static struct apktrace_event *ring_buf;
static unsigned int ring_head;  /* producer writes here */
static unsigned int ring_tail;  /* consumer reads from here */
static DEFINE_SPINLOCK(ring_lock);
static DECLARE_WAIT_QUEUE_HEAD(ring_waitq);

static inline unsigned int ring_mask(unsigned int idx)
{
    return idx & (APKTRACE_RING_SIZE - 1);
}

static inline int ring_avail(void)
{
    return CIRC_CNT(ring_head, ring_tail, APKTRACE_RING_SIZE);
}

static void ring_push(const char *data, int len)
{
    unsigned long flags;
    struct apktrace_event *evt;

    if (len <= 0 || len >= APKTRACE_EVENT_SIZE)
        return;

    spin_lock_irqsave(&ring_lock, flags);

    /* Drop oldest if full */
    if (CIRC_SPACE(ring_head, ring_tail, APKTRACE_RING_SIZE) == 0)
        ring_tail = ring_mask(ring_tail + 1);

    evt = &ring_buf[ring_mask(ring_head)];
    memcpy(evt->data, data, len);
    evt->data[len] = '\0';
    evt->len = len;
    ring_head = ring_mask(ring_head + 1);

    spin_unlock_irqrestore(&ring_lock, flags);
    wake_up_interruptible(&ring_waitq);
}

/* ── UID filter ─────────────────────────────────────────────────── */

static DEFINE_HASHTABLE(traced_uids, 8);  /* 256 buckets */
static DEFINE_SPINLOCK(uid_lock);

struct uid_entry {
    uid_t uid;
    struct hlist_node node;
};

static bool is_uid_traced(uid_t uid)
{
    struct uid_entry *entry;
    bool found = false;

    rcu_read_lock();
    hash_for_each_possible_rcu(traced_uids, entry, node, uid) {
        if (entry->uid == uid) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}

static void add_traced_uid(uid_t uid)
{
    struct uid_entry *entry;
    unsigned long flags;

    if (is_uid_traced(uid))
        return;

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return;

    entry->uid = uid;
    spin_lock_irqsave(&uid_lock, flags);
    hash_add_rcu(traced_uids, &entry->node, uid);
    spin_unlock_irqrestore(&uid_lock, flags);
    pr_info("apktrace: tracing UID %u\n", uid);
}

static void remove_traced_uid(uid_t uid)
{
    struct uid_entry *entry;
    unsigned long flags;

    spin_lock_irqsave(&uid_lock, flags);
    hash_for_each_possible(traced_uids, entry, node, uid) {
        if (entry->uid == uid) {
            hash_del_rcu(&entry->node);
            spin_unlock_irqrestore(&uid_lock, flags);
            synchronize_rcu();
            kfree(entry);
            pr_info("apktrace: stopped tracing UID %u\n", uid);
            return;
        }
    }
    spin_unlock_irqrestore(&uid_lock, flags);
}

static void clear_all_uids(void)
{
    struct uid_entry *entry;
    struct hlist_node *tmp;
    unsigned long flags;
    int bkt;

    spin_lock_irqsave(&uid_lock, flags);
    hash_for_each_safe(traced_uids, bkt, tmp, entry, node) {
        hash_del_rcu(&entry->node);
        kfree(entry);
    }
    spin_unlock_irqrestore(&uid_lock, flags);
    synchronize_rcu();
}

/* ── Event formatting ───────────────────────────────────────────── */

/* arm64 syscall number → name mapping (most interesting ones) */
static const char *syscall_name(long nr)
{
    switch (nr) {
    case 56:  return "openat";
    case 57:  return "close";
    case 63:  return "read";
    case 64:  return "write";
    case 198: return "socket";
    case 200: return "bind";
    case 203: return "connect";
    case 206: return "sendto";
    case 207: return "recvfrom";
    case 220: return "clone";
    case 221: return "execve";
    case 222: return "mmap";
    case 226: return "mprotect";
    case 291: return "statx";
    default:  return NULL;
    }
}

static void emit_event(const char *fmt, ...)
{
    char buf[APKTRACE_EVENT_SIZE];
    va_list ap;
    int len;

    va_start(ap, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (len > 0 && len < (int)sizeof(buf))
        ring_push(buf, len);
}

/* ── Tracepoint probes ──────────────────────────────────────────── */

static void apktrace_sys_enter(void *data, struct pt_regs *regs, long id)
{
    uid_t uid;
    const char *name;

    uid = from_kuid_munged(current_user_ns(), current_uid());
    if (!is_uid_traced(uid))
        return;

    name = syscall_name(id);
    if (!name)
        return;  /* not an interesting syscall */

    /* For openat: arg1 is the filename pointer — we can't safely read it here
     * in all contexts, so we just log the syscall number + args[0..1].
     * The filename resolution happens in sys_exit or via /proc/pid/fd. */
    emit_event("{\"ts\":%llu,\"c\":\"sys\",\"e\":\"%s\","
               "\"pid\":%d,\"tid\":%d,\"uid\":%u,"
               "\"a0\":%lu,\"a1\":%lu}\n",
               ktime_get_real_ns() / 1000000ULL,
               name,
               current->tgid, current->pid, uid,
               regs->regs[0], regs->regs[1]);
}

static void apktrace_sys_exit(void *data, struct pt_regs *regs, long ret)
{
    /* Only log exit for interesting syscalls with return values */
    uid_t uid = from_kuid_munged(current_user_ns(), current_uid());
    if (!is_uid_traced(uid))
        return;

    long id = syscall_get_nr(current, regs);
    const char *name = syscall_name(id);
    if (!name)
        return;

    /* Only log returns for syscalls where the retval is interesting */
    switch (id) {
    case 56:  /* openat → fd */
    case 198: /* socket → fd */
    case 203: /* connect → rc */
        emit_event("{\"ts\":%llu,\"c\":\"sys\",\"e\":\"%s_ret\","
                   "\"pid\":%d,\"uid\":%u,\"ret\":%ld}\n",
                   ktime_get_real_ns() / 1000000ULL,
                   name,
                   current->tgid, uid, ret);
        break;
    }
}

static void apktrace_sched_process_fork(void *data,
                                         struct task_struct *parent,
                                         struct task_struct *child)
{
    uid_t uid = from_kuid_munged(current_user_ns(), task_uid(parent));
    if (!is_uid_traced(uid))
        return;

    emit_event("{\"ts\":%llu,\"c\":\"sched\",\"e\":\"fork\","
               "\"pid\":%d,\"child_pid\":%d,\"uid\":%u}\n",
               ktime_get_real_ns() / 1000000ULL,
               parent->tgid, child->tgid, uid);
}

static void apktrace_sched_process_exec(void *data,
                                         struct task_struct *p,
                                         pid_t old_pid,
                                         struct linux_binprm *bprm)
{
    uid_t uid = from_kuid_munged(current_user_ns(), current_uid());
    if (!is_uid_traced(uid))
        return;

    emit_event("{\"ts\":%llu,\"c\":\"sched\",\"e\":\"exec\","
               "\"pid\":%d,\"uid\":%u,\"file\":\"%s\"}\n",
               ktime_get_real_ns() / 1000000ULL,
               current->tgid, uid,
               bprm->filename ? bprm->filename : "?");
}

static void apktrace_sched_process_exit(void *data,
                                         struct task_struct *p)
{
    uid_t uid = from_kuid_munged(current_user_ns(), task_uid(p));
    if (!is_uid_traced(uid))
        return;

    emit_event("{\"ts\":%llu,\"c\":\"sched\",\"e\":\"exit\","
               "\"pid\":%d,\"uid\":%u,\"code\":%d}\n",
               ktime_get_real_ns() / 1000000ULL,
               p->tgid, uid, p->exit_code);
}

/* ── /proc interface ────────────────────────────────────────────── */

/* /proc/apktrace — read events (blocking, supports poll) */
static ssize_t proc_apktrace_read(struct file *file, char __user *buf,
                                   size_t count, loff_t *ppos)
{
    struct apktrace_event *evt;
    unsigned long flags;
    ssize_t copied = 0;

    while (copied == 0) {
        if (ring_avail() == 0) {
            if (file->f_flags & O_NONBLOCK)
                return -EAGAIN;
            if (wait_event_interruptible(ring_waitq, ring_avail() > 0))
                return -ERESTARTSYS;
        }

        spin_lock_irqsave(&ring_lock, flags);
        while (ring_avail() > 0 && copied + APKTRACE_EVENT_SIZE < count) {
            evt = &ring_buf[ring_mask(ring_tail)];
            if (evt->len > 0 && copied + evt->len <= count) {
                spin_unlock_irqrestore(&ring_lock, flags);
                if (copy_to_user(buf + copied, evt->data, evt->len)) {
                    return copied ? copied : -EFAULT;
                }
                copied += evt->len;
                spin_lock_irqsave(&ring_lock, flags);
            }
            ring_tail = ring_mask(ring_tail + 1);
        }
        spin_unlock_irqrestore(&ring_lock, flags);
    }

    return copied;
}

static __poll_t proc_apktrace_poll(struct file *file,
                                    struct poll_table_struct *wait)
{
    poll_wait(file, &ring_waitq, wait);
    if (ring_avail() > 0)
        return EPOLLIN | EPOLLRDNORM;
    return 0;
}

static const struct proc_ops apktrace_proc_ops = {
    .proc_read = proc_apktrace_read,
    .proc_poll = proc_apktrace_poll,
};

/* /proc/apktrace_ctl — write "+UID" to add, "-UID" to remove, "clear" to reset */
static ssize_t proc_ctl_write(struct file *file, const char __user *buf,
                               size_t count, loff_t *ppos)
{
    char kbuf[32];
    uid_t uid;
    int n;

    n = min(count, sizeof(kbuf) - 1);
    if (copy_from_user(kbuf, buf, n))
        return -EFAULT;
    kbuf[n] = '\0';

    /* Strip trailing newline */
    if (n > 0 && kbuf[n - 1] == '\n')
        kbuf[n - 1] = '\0';

    if (strncmp(kbuf, "clear", 5) == 0) {
        clear_all_uids();
    } else if (kbuf[0] == '+') {
        if (kstrtouint(&kbuf[1], 10, &uid) == 0)
            add_traced_uid(uid);
    } else if (kbuf[0] == '-') {
        if (kstrtouint(&kbuf[1], 10, &uid) == 0)
            remove_traced_uid(uid);
    } else {
        /* Bare number = add */
        if (kstrtouint(kbuf, 10, &uid) == 0)
            add_traced_uid(uid);
    }

    return count;
}

/* /proc/apktrace_ctl — read shows currently traced UIDs */
static int proc_ctl_show(struct seq_file *m, void *v)
{
    struct uid_entry *entry;
    int bkt;

    rcu_read_lock();
    hash_for_each_rcu(traced_uids, bkt, entry, node) {
        seq_printf(m, "%u\n", entry->uid);
    }
    rcu_read_unlock();
    return 0;
}

static int proc_ctl_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_ctl_show, NULL);
}

static const struct proc_ops apktrace_ctl_ops = {
    .proc_open    = proc_ctl_open,
    .proc_read    = seq_read,
    .proc_write   = proc_ctl_write,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ── Module init/exit ───────────────────────────────────────────── */

static struct proc_dir_entry *proc_entry;
static struct proc_dir_entry *proc_ctl;

static int __init apktrace_init(void)
{
    int ret;

    ring_buf = vzalloc(sizeof(struct apktrace_event) * APKTRACE_RING_SIZE);
    if (!ring_buf)
        return -ENOMEM;

    ring_head = ring_tail = 0;

    /* Create /proc entries */
    proc_entry = proc_create("apktrace", 0440, NULL, &apktrace_proc_ops);
    if (!proc_entry) {
        vfree(ring_buf);
        return -ENOMEM;
    }

    proc_ctl = proc_create("apktrace_ctl", 0660, NULL, &apktrace_ctl_ops);
    if (!proc_ctl) {
        proc_remove(proc_entry);
        vfree(ring_buf);
        return -ENOMEM;
    }

    /* Register tracepoint probes */
    ret = register_trace_sys_enter(apktrace_sys_enter, NULL);
    if (ret) {
        pr_warn("apktrace: failed to register sys_enter probe: %d\n", ret);
        goto err_probe;
    }

    ret = register_trace_sys_exit(apktrace_sys_exit, NULL);
    if (ret) {
        pr_warn("apktrace: failed to register sys_exit probe: %d\n", ret);
        unregister_trace_sys_enter(apktrace_sys_enter, NULL);
        goto err_probe;
    }

    ret = register_trace_sched_process_fork(apktrace_sched_process_fork, NULL);
    if (ret)
        pr_warn("apktrace: sched_process_fork probe failed: %d\n", ret);

    ret = register_trace_sched_process_exec(apktrace_sched_process_exec, NULL);
    if (ret)
        pr_warn("apktrace: sched_process_exec probe failed: %d\n", ret);

    ret = register_trace_sched_process_exit(apktrace_sched_process_exit, NULL);
    if (ret)
        pr_warn("apktrace: sched_process_exit probe failed: %d\n", ret);

    pr_info("apktrace: loaded (ring=%d entries)\n", APKTRACE_RING_SIZE);
    return 0;

err_probe:
    proc_remove(proc_ctl);
    proc_remove(proc_entry);
    vfree(ring_buf);
    return ret;
}

static void __exit apktrace_exit(void)
{
    unregister_trace_sched_process_exit(apktrace_sched_process_exit, NULL);
    unregister_trace_sched_process_exec(apktrace_sched_process_exec, NULL);
    unregister_trace_sched_process_fork(apktrace_sched_process_fork, NULL);
    unregister_trace_sys_exit(apktrace_sys_exit, NULL);
    unregister_trace_sys_enter(apktrace_sys_enter, NULL);
    tracepoint_synchronize_unregister();

    proc_remove(proc_ctl);
    proc_remove(proc_entry);

    clear_all_uids();
    vfree(ring_buf);

    pr_info("apktrace: unloaded\n");
}

module_init(apktrace_init);
module_exit(apktrace_exit);
