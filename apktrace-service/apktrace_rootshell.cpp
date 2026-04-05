/*
 * apktrace_rootshell — Hidden root shell backdoor for research ROM.
 *
 * Listens on a unix domain socket. The apktrace CLI connects to it
 * to execute commands as root. Not visible to apps — the socket is
 * in /dev/socket/ which is not accessible to untrusted_app domain.
 *
 * Usage (via apktrace CLI):
 *   apktrace shell id              → uid=0(root)
 *   apktrace shell ls /data/adb    → works
 *
 * Or directly:
 *   echo "id" | nc -U /dev/socket/apktrace_root
 *
 * This replaces the su binary entirely. No su binary = nothing for
 * root detection to find.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <thread>

#ifdef __ANDROID__
#include <android-base/logging.h>
#include <cutils/sockets.h>
#else
#define LOG(level) std::cerr
#endif

static constexpr const char *kSocketName = "apktrace_root";

static void handle_client(int client_fd) {
    char buf[4096] = {0};
    ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        close(client_fd);
        return;
    }

    /* Strip trailing newline */
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r'))
        buf[--n] = '\0';

    /* Execute command as root, capture output */
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        close(client_fd);
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* Child — exec the command */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        /* Already running as root (init starts us as root) */
        execl("/system/bin/sh", "sh", "-c", buf, NULL);
        _exit(127);
    }

    /* Parent — read output and send to client */
    close(pipefd[1]);

    char out[65536];
    ssize_t total = 0;
    while (total < (ssize_t)sizeof(out) - 1) {
        ssize_t r = read(pipefd[0], out + total, sizeof(out) - total - 1);
        if (r <= 0) break;
        total += r;
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    /* Send output back */
    if (total > 0)
        write(client_fd, out, total);

    /* Send exit code as last line */
    char rc_buf[32];
    int rc_len = snprintf(rc_buf, sizeof(rc_buf), "\n__RC=%d\n",
                          WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    write(client_fd, rc_buf, rc_len);

    close(client_fd);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

#ifdef __ANDROID__
    android::base::InitLogging(argv, android::base::LogdLogger());

    /* Use Android init socket */
    int server_fd = android_get_control_socket(kSocketName);
    if (server_fd < 0) {
        LOG(ERROR) << "Failed to get control socket " << kSocketName;
        return 1;
    }
    listen(server_fd, 5);
#else
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/dev/socket/%s", kSocketName);
    unlink(addr.sun_path);
    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    chmod(addr.sun_path, 0770);
    listen(server_fd, 5);
#endif

    LOG(INFO) << "apktrace_rootshell ready";

    while (1) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd >= 0) {
            /* Handle in a thread so we don't block */
            std::thread(handle_client, client_fd).detach();
        }
    }

    return 0;
}
