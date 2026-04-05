# AOSP Security Research ROM — Instrumentation Plan

**Target:** Pixel 8a (akita), Android 16 (Baklava), Kernel 6.1 Tensor G3
**Product:** `aosp_akita_research-trunk_staging-userdebug`
**AOSP tree:** `~/aosp` @ android-16.0.0_r4, device trees from main

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  Fleet Orchestrator  (fleet/trace_worker.py)                        │
│    - RomTraceBackend replaces Frida + eBPF backends                 │
│    - adb shell apktrace start/stop/dump <pkg>                      │
│    - OR: HTTP GET http://<device>:8642/traces/<pkg>                 │
└──────────┬───────────────────────────────────────────────────────────┘
           │ ADB / HTTP
┌──────────▼───────────────────────────────────────────────────────────┐
│  apktrace_collector  (C++ daemon, /system/bin/apktrace_collector)   │
│    Config: /data/misc/apktrace/config.json                          │
│    Per-package ring buffers → /data/local/tmp/apktrace/<pkg>/       │
│    CLI: apktrace {start|stop|dump|config|status} <pkg>              │
│    HTTP server on port 8642 (optional)                              │
└───┬──────────┬──────────────┬──────────────────┬─────────────────────┘
    │          │              │                  │
┌───▼────┐ ┌──▼──────┐ ┌────▼──────────┐ ┌────▼────────────┐
│ TLS    │ │Framework│ │ eBPF/kernel   │ │ TEE/Keystore2   │
│ plain- │ │API trace│ │ tracing       │ │ instrumentation │
│ text   │ │(Java)   │ │(.bpf.c)       │ │(Rust + C++)     │
│(boring │ │         │ │               │ │                 │
│ ssl)   │ │         │ │               │ │                 │
└────────┘ └─────────┘ └───────────────┘ └─────────────────┘
```

## Output Format (unified across all layers)

```json
{"ts":1234567890,"c":"tls","e":"write","pid":12345,"dst":"1.2.3.4:443","len":256,"sni":"api.example.com"}
{"ts":1234567891,"c":"fs","e":"openat","pid":12345,"path":"/data/data/com.app/db","fd":7}
{"ts":1234567892,"c":"tee","e":"key_sign","pid":12345,"alg":"EC","uid":10123}
{"ts":1234567893,"c":"lifecycle","e":"activity_start","pkg":"com.app","cls":"MainActivity"}
{"ts":1234567894,"c":"binder","e":"txn","from_pid":12345,"to_pid":1000,"code":3}
```

Categories: `tls`, `fs`, `net`, `exec`, `mem`, `load`, `binder`, `lifecycle`,
`provider`, `location`, `account`, `tee`, `sched`

---

## Phase 1: Build Infrastructure

No functional changes — just the product definition and build plumbing.

### 1A. Research product makefile

**New file:** `device/google/akita/aosp_akita_research.mk`

```makefile
$(call inherit-product, device/google/akita/aosp_akita.mk)

PRODUCT_NAME := aosp_akita_research
PRODUCT_MODEL := Pixel 8a Research

# System properties — all tracing off by default
PRODUCT_PRODUCT_PROPERTIES += \
    persist.apktrace.enabled=0 \
    persist.apktrace.http_port=8642 \
    persist.apktrace.tls_plaintext=0 \
    persist.apktrace.tls_keylog=0

# Our packages
PRODUCT_PACKAGES += \
    apktrace_collector \
    apktrace_cli

# eBPF programs (installed to /system/etc/bpf/)
PRODUCT_PACKAGES += \
    apktrace_syscalls.bpf \
    apktrace_binder.bpf \
    apktrace_sched.bpf \
    apktrace_net.bpf
```

**Modify:** `device/google/akita/AndroidProducts.mk` — add to PRODUCT_MAKEFILES and
COMMON_LUNCH_CHOICES.

### 1B. Verify it boots

```bash
lunch aosp_akita_research-trunk_staging-userdebug
m -j$(nproc)
# Flash, confirm boot, confirm no regressions
```

---

## Phase 2: BoringSSL TLS Plaintext Capture

This is the biggest win — captures ALL decrypted TLS traffic on device. Eliminates
the need for MITM proxy, CA cert injection, and cert pinning bypass.

### 2A. SSL_read/SSL_write hooks (real-time plaintext logging)

**File to modify:** `external/boringssl/src/ssl/ssl_lib.cc`

Hook `SSL_read()` and `SSL_write()` to log decrypted buffers. The hooks:
- Check `persist.apktrace.tls_plaintext` sysprop (skip if 0)
- Look up calling PID in the traced-PIDs set (shared memory or sysprop list)
- Extract: remote IP:port from the underlying socket fd, SNI from the SSL session
- Write to a unix domain socket or shared ring buffer that apktrace_collector reads
- Log: timestamp, pid, uid, direction (read/write), dst addr, SNI hostname, data length,
  first N bytes or SHA256 of payload

```c
// In SSL_read(), after successful decryption:
if (apktrace_tls_enabled()) {
    apktrace_tls_log(ssl, buf, ret, APKTRACE_TLS_READ);
}

// In SSL_write(), before encryption:
if (apktrace_tls_enabled()) {
    apktrace_tls_log(ssl, buf, num, APKTRACE_TLS_WRITE);
}
```

**New file:** `external/boringssl/src/ssl/apktrace_tls.cc`

Contains:
- `apktrace_tls_enabled()` — checks sysprop + PID filter (cached, not per-call)
- `apktrace_tls_log(SSL *ssl, const void *buf, int len, int direction)` — extracts
  connection info from SSL/BIO, formats event, writes to ring buffer
- `apktrace_tls_init()` — called once at process start, sets up shared memory
- Socket peer address extraction via `getpeername()` on the BIO fd
- SNI extraction via `SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)`

**New file:** `external/boringssl/src/ssl/apktrace_tls.h`

Event struct:
```c
struct apktrace_tls_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t uid;
    uint8_t  direction;       // 0=read, 1=write
    uint16_t dst_port;
    uint8_t  dst_addr[16];    // IPv4-mapped-IPv6
    uint8_t  addr_family;     // AF_INET or AF_INET6
    char     sni[256];
    uint32_t data_len;
    uint8_t  data_sha256[32];
    uint8_t  data_head[256];  // first 256 bytes of plaintext
};
```

**Modify:** `external/boringssl/src/ssl/CMakeLists.txt` and/or `Android.bp` to include
the new source file.

### 2B. SSLKEYLOGFILE callback (session key export for Wireshark)

**File to modify:** `external/boringssl/src/ssl/ssl_lib.cc`

In `SSL_CTX_new()` (or a global init path), register a keylog callback when
`persist.apktrace.tls_keylog` is set:

```c
static void apktrace_keylog_callback(const SSL *ssl, const char *line) {
    // Append to /data/local/tmp/apktrace/sslkeylog.txt
    int fd = open("/data/local/tmp/apktrace/sslkeylog.txt",
                  O_WRONLY | O_CREAT | O_APPEND, 0660);
    if (fd >= 0) {
        write(fd, line, strlen(line));
        write(fd, "\n", 1);
        close(fd);
    }
}

// In SSL_CTX initialization path:
if (apktrace_keylog_enabled()) {
    SSL_CTX_set_keylog_callback(ctx, apktrace_keylog_callback);
}
```

Pair with on-device packet capture:
```bash
# On device:
tcpdump -i any -w /data/local/tmp/apktrace/capture.pcap &

# Pull both files, open in Wireshark:
# Edit → Preferences → TLS → (Pre)-Master-Secret log filename → sslkeylog.txt
```

This gives full pcap-level forensic analysis with decryption — every packet, every
header, every certificate, every handshake parameter.

### 2C. Performance considerations

- The sysprop check is cached per-process (read once at SSL_CTX creation)
- PID filter check is a hash lookup in shared memory (~50ns)
- When disabled: zero overhead (function pointer is NULL)
- When enabled: ~1μs per SSL_read/SSL_write for the logging path
- Ring buffer is lock-free (producer-consumer with atomic indices)
- Data head capture is configurable (0 = hash only, 256 = default, -1 = full payload)

---

## Phase 3: Trace Collection Service (apktrace_collector)

### 3A. Daemon

**New directory:** `system/extras/apktrace/`

Files:
- `collector/main.cpp` — daemon entry point, signal handling
- `collector/config.cpp/.h` — JSON config at `/data/misc/apktrace/config.json`
- `collector/ring_buffer.cpp/.h` — per-package in-memory circular buffer
- `collector/ebpf_reader.cpp/.h` — reads BPF ring buffers, resolves PID→package
- `collector/tls_reader.cpp/.h` — reads BoringSSL shared ring buffer
- `collector/tee_reader.cpp/.h` — reads keystore2/trusty logs from logcat
- `collector/framework_reader.cpp/.h` — reads framework trace files
- `collector/http_server.cpp/.h` — minimal HTTP server for fleet pull
- `collector/Android.bp` — builds `apktrace_collector` binary

### 3B. CLI tool

- `cli/main.cpp` — builds as `/system/bin/apktrace`
- Commands:
  - `apktrace start <pkg> [--categories=tls,fs,binder,tee]`
  - `apktrace stop <pkg>`
  - `apktrace dump <pkg> [--format=jsonl] [--since=<timestamp>]`
  - `apktrace status` — traced packages, buffer usage, event counts per category
  - `apktrace config set <key> <value>`
  - `apktrace flush` — force flush all buffers to disk
  - `apktrace keylog {start|stop}` — toggle SSLKEYLOGFILE
  - `apktrace pcap {start|stop}` — toggle tcpdump capture

### 3C. Init service

**New file:** `system/extras/apktrace/apktrace_collector.rc`

```
service apktrace_collector /system/bin/apktrace_collector
    class late_start
    user system
    group system readproc net_raw
    disabled

on property:persist.apktrace.enabled=1
    mkdir /data/misc/apktrace 0770 system system
    mkdir /data/local/tmp/apktrace 0770 system shell
    start apktrace_collector
```

### 3D. Config

`/data/misc/apktrace/config.json`:
```json
{
  "version": 1,
  "global": {
    "ring_buffer_size_mb": 4,
    "flush_interval_sec": 30,
    "http_enabled": true,
    "http_port": 8642,
    "tls_data_head_bytes": 256,
    "tls_capture_full_payload": false
  },
  "packages": {
    "com.whatsapp": {
      "enabled": true,
      "categories": ["tls", "fs", "binder", "tee", "lifecycle"]
    }
  }
}
```

---

## Phase 4: eBPF Kernel Tracing

### 4A. eBPF programs

**New directory:** `system/bpf/progs/apktrace/`

**Shared header — `apktrace_common.h`:**
```c
struct apktrace_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tid;
    uint32_t uid;
    uint16_t event_type;    // enum: SYSCALL, BINDER, FORK, EXEC, EXIT, NET
    uint16_t payload_len;
    uint8_t  payload[128];  // syscall args, path prefix, addr, etc.
};

// PID filter — populated by apktrace_collector via bpf map update
// NOTE: AOSP requires permission-variant macros (not bare DEFINE_BPF_MAP)
DEFINE_BPF_MAP_GRW(traced_pids, HASH, uint32_t, uint8_t, 1024, AID_SYSTEM);
DEFINE_BPF_RINGBUF(apktrace_rb, struct apktrace_event, 1048576, AID_ROOT, AID_SYSTEM, 0660);
```

**`apktrace_syscalls.c`:**
- Attaches to `raw_syscalls/sys_enter`
- Checks PID against `traced_pids` map in-kernel (solves the set_event_pid issue)
- Filters to interesting syscall NRs: 56 (openat), 57 (close), 63 (read), 64 (write),
  198 (socket), 203 (connect), 206 (sendto), 207 (recvfrom), 220 (clone),
  221 (execve), 222 (mmap), 226 (mprotect), 291 (statx)
- For openat: reads first 128 bytes of filename from arg[1]
- For connect: reads sockaddr from arg[1] (IP + port)
- Outputs to ring buffer

**`apktrace_binder.c`:**
- Attaches to `binder/binder_transaction`, `binder/binder_ioctl`
- PID filter via `traced_pids` map
- Logs: from_pid, to_pid, transaction code, data_size, flags

**`apktrace_sched.c`:**
- Attaches to `sched/sched_process_fork`, `sched/sched_process_exec`,
  `sched/sched_process_exit`, `task/task_newtask`
- On fork: if parent PID is in `traced_pids`, auto-add child PID (fork following)
- On exit: remove PID from `traced_pids`
- Logs: event type, parent/child PIDs, comm name

**`apktrace_net.c`:**
- Attaches to `net/net_dev_xmit`, `signal/signal_generate`
- PID filter
- Network: logs skb len, dev name
- Signal: logs sig number, target PID

### 4B. Build rules

**`system/bpf/progs/Android.bp`** (add to existing file):
```
libbpf_prog {
    name: "apktrace_syscalls.bpf",
    srcs: ["apktrace/apktrace_syscalls.c"],
    header_libs: ["android_bpf_defs"],
}

libbpf_prog {
    name: "apktrace_binder.bpf",
    srcs: ["apktrace/apktrace_binder.c"],
    header_libs: ["android_bpf_defs"],
}

libbpf_prog {
    name: "apktrace_sched.bpf",
    srcs: ["apktrace/apktrace_sched.c"],
    header_libs: ["android_bpf_defs"],
}

libbpf_prog {
    name: "apktrace_net.bpf",
    srcs: ["apktrace/apktrace_net.c"],
    header_libs: ["android_bpf_defs"],
}
```

Programs install to `/system/etc/bpf/` and are loaded by `bpfloader` at boot.
Maps pin to `/sys/fs/bpf/map_apktrace_*`.
Programs pin to `/sys/fs/bpf/prog_apktrace_*`.

### 4C. PID management

When `apktrace start <pkg>` is called:
1. Collector resolves package → UID via `pm list packages -U`
2. Finds all PIDs for that UID via `/proc/*/status`
3. Inserts each PID into `traced_pids` BPF map
4. Fork following (in `apktrace_sched.c`) auto-adds child PIDs
5. If app isn't running yet, collector watches for process start events and adds PID
   when the package launches

---

## Phase 5: Framework API Tracing

### 5A. Trace service

**New package:** `frameworks/base/services/core/java/com/android/server/apktrace/`

Files:
- `ApkTraceService.java` — system service, manages config, exposes AIDL interface
- `ApkTraceLogger.java` — static logger, called from hook points
  - `isTraced(String pkg)` — hash lookup, returns in <100ns
  - `log(String pkg, String category, String event, Bundle data)` — formats JSON, writes
    to per-package file at `/data/local/tmp/apktrace/<pkg>/framework.jsonl`
- `ApkTraceConfig.java` — reads config, maintains traced package set

### 5B. Hook points (3-5 lines each, guarded by isTraced check)

**ActivityManagerService** (`services/core/java/com/android/server/am/`):
- `ActivityManagerService.java` → `startProcessLocked()` — log process start
- `ActivityManagerService.java` → `broadcastIntentLocked()` — log broadcasts
  (action, target package, extras keys)
- `ActivityTaskManagerService.java` → `startActivityAsUser()` — log activity starts
  (component, action, flags)

**ContentResolver** (`core/java/android/content/ContentResolver.java`):
- `query()` — log URI, calling package, projection columns
- `insert()` / `update()` / `delete()` — log URI, calling package

**PackageManagerService** (`services/core/java/com/android/server/pm/ComputerEngine.java`):
- `getPackageInfo()` — log queried package, flags
- `checkUidPermission()` — log permission name, UID, result
  (NOTE: ComputerEngine has `checkUidPermission()`, not `checkPermission()`)

**LocationManager** (`core/java/android/location/LocationManager.java`):
- `requestLocationUpdates()` — log provider, interval, calling package
  (NOTE: hook is client-side — LocationManagerService does NOT have this method.
  The client-side LocationManager.java has it at line 1215+. Alternatively,
  hook the ILocationManager AIDL stub's onTransact() for server-side capture.)

**AccountManagerService** (`services/core/java/com/android/server/accounts/`):
- `getAccounts()` — log account types requested, calling package

### 5C. Registration

**Modify:** `frameworks/base/services/java/com/android/server/SystemServer.java`

In `startOtherServices()`:
```java
t.traceBegin("StartApkTraceService");
mSystemServiceManager.startService(ApkTraceService.class);
t.traceEnd();
```

---

## Phase 6: TEE / Trusty IPC Logging

### 6A. Keystore2 audit extension

**Modify:** `system/security/keystore2/src/audit_log.rs`

Add new log functions:
```rust
pub fn log_key_operation(calling_uid: u32, key_id: i64, purpose: KeyPurpose,
                         algorithm: Algorithm, key_params: &[KeyParameter]) {
    // Format as JSON, write to logcat with tag "ApkTraceTEE"
    // Detect attestation: check for Tag::ATTESTATION_CHALLENGE
    // Detect Play Integrity: attestation + calling_uid maps to com.google.android.gms
}
```

**Modify:** `system/security/keystore2/src/security_level.rs`

In `create_operation()`:
```rust
// After access check, before forwarding to KeyMint:
audit_log::log_key_operation(caller_uid, key_id_guard.id(),
    op_params.purpose, key_entry.algorithm(), &op_params.params);
```

In `generate_key()`:
```rust
// Log key generation with attestation detection
let has_attestation = params.iter().any(|p| p.tag == Tag::ATTESTATION_CHALLENGE);
audit_log::log_key_generation(caller_uid, &params, has_attestation);
```

### 6B. Trusty HAL timing wrapper

**Modify:** `system/core/trusty/keymaster/ipc/trusty_keymaster_ipc.cpp`

Wrap `trusty_keymaster_call_2()`:

NOTE: Actual signature is `std::variant<int, std::vector<uint8_t>>` return type,
not `int`. The wrapper must handle the variant return.

```cpp
// Actual signature (line 78 of trusty_keymaster_ipc.cpp):
// std::variant<int, std::vector<uint8_t>> trusty_keymaster_call_2(
//     uint32_t cmd, void* in, uint32_t in_size)

std::variant<int, std::vector<uint8_t>> trusty_keymaster_call_2(
        uint32_t cmd, void* in, uint32_t in_size) {
    auto start = std::chrono::steady_clock::now();

    // original implementation...
    auto result = /* original call */;

    auto elapsed = std::chrono::steady_clock::now() - start;
    size_t out_size = std::holds_alternative<std::vector<uint8_t>>(result)
                      ? std::get<std::vector<uint8_t>>(result).size() : 0;
    ALOG(LOG_INFO, "ApkTraceTEE",
         "{\"c\":\"tee\",\"e\":\"trusty_call\",\"cmd\":%u,\"in\":%u,"
         "\"out\":%zu,\"dur_us\":%lld,\"uid\":%d}",
         cmd, in_size, out_size,
         std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count(),
         getuid());
    return result;
}
```

### 6C. Trusty driver tracepoints (if available)

Check at build time if `events/trusty/` exists in tracefs. If so, enable via an
eBPF program (`apktrace_trusty.c`) that attaches to `trusty/trusty_smc` and
`trusty/trusty_smc_done`. If not available (likely), rely on 6A + 6B which capture
the same information from the normal-world side.

### 6D. Play Integrity detection

When keystore2 sees:
1. `Tag::ATTESTATION_CHALLENGE` present in key generation params
2. Calling UID maps to `com.google.android.gms` (UID resolved via PackageManager)

Log as: `{"c":"tee","e":"play_integrity","uid":10153,"pkg":"com.google.android.gms","challenge_len":32}`

The requesting app (which triggered GMS to do attestation) can be correlated by
looking at the binder transaction log — the binder call from the app to GMS will
appear just before the attestation request.

---

## Phase 7: Fleet Integration

### 7A. RomTraceBackend

**Modify:** `~/apk-scraper/fleet/trace_worker.py`

```python
class RomTraceBackend(TracingBackend):
    """ROM-level instrumentation — apktrace system service."""
    name = "rom"

    def is_available(self, serial):
        rc, out, _ = fleet_adb.adb(
            ["shell", "which", "apktrace"], serial=serial, timeout=5)
        return rc == 0 and "apktrace" in out

    def start(self, serial, package, staging_dir):
        # Enable tracing globally if not already on
        fleet_adb.adb(["shell", "setprop", "persist.apktrace.enabled", "1"],
                      serial=serial)
        fleet_adb.adb(["shell", "setprop", "persist.apktrace.tls_plaintext", "1"],
                      serial=serial)
        # Start tracing this package
        fleet_adb.adb(["shell", "apktrace", "start", package,
                       "--categories=tls,fs,binder,tee,lifecycle"],
                      serial=serial)
        return True

    def stop(self, serial, package, staging_dir):
        fleet_adb.adb(["shell", "apktrace", "flush"], serial=serial)
        rom_dir = os.path.join(staging_dir, "rom")
        os.makedirs(rom_dir, exist_ok=True)
        fleet_adb.pull_file(serial,
            f"/data/local/tmp/apktrace/{package}/",
            rom_dir)
        fleet_adb.adb(["shell", "apktrace", "stop", package],
                      serial=serial)
        return True

    def requires_running_process(self):
        return False  # eBPF + TLS hooks activate when app starts
```

### 7B. Backend priority update

```python
DEFAULT_BACKEND_CLASSES = [RomTraceBackend, FridaBackend, EbpfBackend, StraceBackend]
```

ROM backend is preferred when available. Falls back to Frida/eBPF for non-research
devices (e.g., the LG farm phones).

---

## SELinux Policy

**New files in** `device/google/akita-sepolicy/vendor/`:

- `apktrace_collector.te` — type and permissions
- `file_contexts` — label apktrace files
- `property_contexts` — label persist.apktrace.* properties

Key permissions:
- Read BPF maps/progs at `/sys/fs/bpf/map_apktrace_*`
- Read/write `/data/local/tmp/apktrace/`
- Read `/data/misc/apktrace/`
- Read `/proc/<pid>/cmdline` (PID→package resolution)
- Listen TCP 8642
- Read logcat security buffer
- Create/read unix domain sockets (BoringSSL → collector)

During development: `permissive apktrace_collector;` (userdebug allows this).
Tighten in production.

---

## Implementation Order

| Phase | What | New files | Modified files | Risk |
|-------|------|-----------|---------------|------|
| 1 | Build infra | 1 mk | 1 mk | None — just a product def |
| 2 | BoringSSL TLS capture | 2 (cc, h) | 1 (ssl_lib.cc) | Low — guarded by sysprop |
| 3 | apktrace_collector | ~12 | 0 | Low — new standalone daemon |
| 4 | eBPF programs | 5 (4 bpf + bp) | 0 | Med — BPF verifier |
| 5 | Framework API tracing | 4 (java) | ~7 (hook points) | Med — framework changes |
| 6 | TEE instrumentation | 0 | 3 (rs, rs, cpp) | Low — logging only |
| 7 | Fleet integration | 0 | 2 (py) | None — Python changes |

**Phase 1 depends on:** test build completing (in progress)
**Phase 2 depends on:** Phase 1
**Phase 3 depends on:** Phase 1
**Phase 4 depends on:** Phase 3 (collector reads BPF ring buffer)
**Phase 5 depends on:** Phase 3 (collector reads framework logs)
**Phase 6 depends on:** Phase 3 (collector reads TEE logs)
**Phase 7 depends on:** Phase 3

**Phases 2, 4, 5, 6 are independent of each other** — can be built in parallel
after Phase 3 is done.

---

## Data Flow Summary

```
App calls SSL_write("GET /api/data HTTP/1.1")
  → BoringSSL ssl_lib.cc logs plaintext + dst + SNI
    → unix socket → apktrace_collector
      → per-package ring buffer → JSON line
        → /data/local/tmp/apktrace/com.app/tls.jsonl

App calls openat("/data/data/com.app/databases/main.db")
  → kernel raw_syscalls/sys_enter tracepoint
    → apktrace_syscalls.bpf checks traced_pids map → match
      → BPF ring buffer → apktrace_collector
        → per-package ring buffer → JSON line
          → /data/local/tmp/apktrace/com.app/ebpf.jsonl

App calls KeyStore.sign(key, data)
  → keystore2 security_level.rs create_operation()
    → audit_log::log_key_operation() → logcat "ApkTraceTEE"
      → apktrace_collector reads logcat
        → per-package ring buffer → JSON line
          → /data/local/tmp/apktrace/com.app/tee.jsonl

Fleet orchestrator:
  adb shell apktrace start com.app --categories=tls,fs,tee
  # ... app runs ...
  adb shell apktrace dump com.app > traces.jsonl
  adb shell apktrace stop com.app
```

---

## What This Replaces

| Old approach | Problem | New approach |
|-------------|---------|-------------|
| Frida spawn + hooks | Spawn timeout, anti-frida, API breaks | BoringSSL + framework hooks |
| tracefs raw_syscalls | set_event_pid broken, shell quoting | eBPF with in-kernel PID filter |
| MITM proxy + CA cert | Cert pinning, per-app config, router HW | BoringSSL SSL_read/SSL_write |
| strace | ptrace detection, huge output | eBPF filtered to interesting syscalls |

## What This Enables (future)

- TEE vulnerability research (Phase 6 provides the call-level data)
- Cross-app correlation (binder tracing shows IPC between apps)
- TLS traffic analysis without any network infra
- Longitudinal behavioral fingerprinting (same app, different versions)
- Hardware attestation tracking (which apps check device integrity)

---

## TEE Vulnerability Research Addendum

### Trusty OS Build
- `generic-arm64-debug` target builds clean (lk.bin = 16MB)
- IPC tracing confirmed in binary (TEE_IPC strings present)
- BL31 SMC tracing added to trusty.c and ven_el3_svc.c
- Build: `python3 trusty/vendor/google/aosp/scripts/build.py generic-arm64-debug`

### Platform Code Status
Google's Tensor/Exynos-specific Trusty platform repos exist but are access-restricted:
- `trusty/device/google/zuma` — restricted
- `trusty/device/samsung` — restricted
- `trusty/platform/google/zuma` — restricted

Without this code, the generic-arm64 Trusty build likely won't boot on the Pixel 8a
due to missing hardware init (memory carveouts, interrupt routing, peripheral config).

### Approaches to Get Trusty Running on Real Hardware

1. **Extract from stock tzsw** — Pull `/dev/block/by-name/tzsw_b` from the device,
   reverse engineer the platform init (memory maps, MMIO regions, interrupt config),
   and port to the generic-arm64 platform.

2. **Samsung open source** — Check opensource.samsung.com for Exynos 2400 / Tensor G3
   TEE platform code. Samsung is required to publish GPL code but Trusty (BSD license)
   may not be included.

3. **Hybrid approach** — Use the stock tzsw binary but patch in our tracing hooks via
   binary patching. Find the IPC handler functions in the stock binary, add trampolines
   to our logging code. Avoids needing full platform source.

4. **QEMU testing** — Test IPC tracing in emulation first. QEMU prebuilt is at
   `prebuilts/android-emulator/trusty-x86_64/bin/qemu-system-aarch64`.

### BL31/EL3 Attack Surface (Documented)
- `trusty_smc_handler()` — all SMC dispatch, args passed to Trusty with no validation
- `trusty_set_fiq_handler()` — sets handler PC/SP from normal world args
- `ven_el3_svc_handler()` — vendor EL3 services
- No Samsung/Exynos-specific SiP handlers visible in public code (proprietary)

### Tracing Chain (Complete)
```
/proc/apktrace      → app syscalls (kernel module)
tls_plaintext.jsonl → decrypted TLS (BoringSSL hooks)
framework.jsonl     → Java API calls (framework hooks)
logcat ApkTraceTEE  → keystore2 operations (Rust hooks)
/dev/trusty-log0    → TEE IPC per-TA (Trusty kernel hooks)
BL31 console        → raw SMC function IDs (TF-A hooks)
```
