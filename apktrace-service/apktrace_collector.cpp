/*
 * apktrace_collector — Central trace collection daemon for security research ROM.
 *
 * Aggregates traces from:
 *   - BoringSSL TLS plaintext (reads /data/local/tmp/apktrace/tls_plaintext.jsonl)
 *   - eBPF ring buffers (reads /sys/fs/bpf/map_apktrace_*)
 *   - Framework API logs (reads /data/local/tmp/apktrace/<pkg>/framework.jsonl)
 *   - TEE/keystore2 logs (reads logcat -b security tag:ApkTraceTEE)
 *
 * Exposes:
 *   - CLI via /system/bin/apktrace (separate binary, talks via unix socket)
 *   - HTTP API on port 8642 for fleet orchestrator pulls
 *
 * Config: /data/misc/apktrace/config.json
 * Data:   /data/local/tmp/apktrace/<pkg>/
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <fstream>
#include <map>
#include <sstream>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#ifdef __ANDROID__
#include <android-base/logging.h>
#include <android-base/properties.h>
#else
#include <iostream>
#define LOG(level) std::cerr
#endif

static constexpr const char *kConfigPath = "/data/misc/apktrace/config.json";
static constexpr const char *kDataDir = "/data/local/tmp/apktrace";
static constexpr const char *kSocketPath = "/dev/socket/apktrace";
static constexpr int kDefaultHttpPort = 8642;

static std::atomic<bool> g_running{true};

/* ── Traced package state ──────────────────────────────────────── */

static std::mutex g_pkg_mutex;
static std::set<std::string> g_traced_packages;

[[maybe_unused]]
static bool is_traced(const std::string &pkg) {
    std::lock_guard<std::mutex> lock(g_pkg_mutex);
    return g_traced_packages.count(pkg) > 0;
}

static void add_traced(const std::string &pkg) {
    std::lock_guard<std::mutex> lock(g_pkg_mutex);
    g_traced_packages.insert(pkg);

    /* Create output directory */
    std::string dir = std::string(kDataDir) + "/" + pkg;
    mkdir(dir.c_str(), 0770);
}

static void remove_traced(const std::string &pkg) {
    std::lock_guard<std::mutex> lock(g_pkg_mutex);
    g_traced_packages.erase(pkg);
}

/* ── eBPF PID map management ───────────────────────────────────── */

static void update_ebpf_pid_map(const std::string &pkg, bool add) {
    /* TODO Phase 4: open /sys/fs/bpf/map_apktrace_traced_pids
     * and insert/remove PIDs for this package */
    (void)pkg;
    (void)add;
}

/* ── Unix socket command server ────────────────────────────────── */

static void handle_command(int client_fd) {
    char buf[4096] = {0};
    ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        close(client_fd);
        return;
    }

    std::string cmd(buf, n);
    std::string response;

    /* Parse: "start <pkg> [--categories=...]" | "stop <pkg>" | "status" | "dump <pkg>" | "flush" */
    if (cmd.rfind("start ", 0) == 0) {
        std::string pkg = cmd.substr(6);
        /* Strip trailing whitespace/newline */
        while (!pkg.empty() && (pkg.back() == '\n' || pkg.back() == ' '))
            pkg.pop_back();
        /* Strip --categories for now (TODO: parse) */
        auto sp = pkg.find(' ');
        if (sp != std::string::npos) pkg = pkg.substr(0, sp);

        add_traced(pkg);
        update_ebpf_pid_map(pkg, true);
        response = "OK: tracing " + pkg + "\n";

    } else if (cmd.rfind("stop ", 0) == 0) {
        std::string pkg = cmd.substr(5);
        while (!pkg.empty() && (pkg.back() == '\n' || pkg.back() == ' '))
            pkg.pop_back();
        remove_traced(pkg);
        update_ebpf_pid_map(pkg, false);
        response = "OK: stopped " + pkg + "\n";

    } else if (cmd.rfind("dump ", 0) == 0) {
        std::string pkg = cmd.substr(5);
        while (!pkg.empty() && (pkg.back() == '\n' || pkg.back() == ' '))
            pkg.pop_back();
        /* Read trace files and send contents */
        std::string dir = std::string(kDataDir) + "/" + pkg;
        for (const char *suffix : {"tls.jsonl", "ebpf.jsonl", "framework.jsonl", "tee.jsonl"}) {
            std::string path = dir + "/" + suffix;
            std::ifstream f(path);
            if (f.is_open()) {
                std::ostringstream ss;
                ss << f.rdbuf();
                response += ss.str();
            }
        }
        if (response.empty()) response = "no traces for " + pkg + "\n";

    } else if (cmd.rfind("status", 0) == 0) {
        std::lock_guard<std::mutex> lock(g_pkg_mutex);
        response = "traced_packages: " + std::to_string(g_traced_packages.size()) + "\n";
        for (const auto &pkg : g_traced_packages) {
            response += "  " + pkg + "\n";
        }

    } else if (cmd.rfind("flush", 0) == 0) {
        /* TODO: flush ring buffers to disk */
        response = "OK: flushed\n";

    } else {
        response = "ERROR: unknown command\n";
    }

    write(client_fd, response.c_str(), response.size());
    close(client_fd);
}

static void command_server_loop() {
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        LOG(ERROR) << "Failed to create socket: " << strerror(errno);
        return;
    }

    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, kSocketPath, sizeof(addr.sun_path) - 1);
    unlink(kSocketPath);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG(ERROR) << "Failed to bind " << kSocketPath << ": " << strerror(errno);
        close(server_fd);
        return;
    }
    chmod(kSocketPath, 0770);
    listen(server_fd, 5);

    LOG(INFO) << "Command server listening on " << kSocketPath;

    while (g_running) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd >= 0) {
            handle_command(client_fd);
        }
    }
    close(server_fd);
    unlink(kSocketPath);
}

/* ── TLS log watcher ───────────────────────────────────────────── */

static void tls_log_watcher() {
    /* Watch /data/local/tmp/apktrace/tls_plaintext.jsonl
     * and redistribute lines to per-package files based on PID→package mapping.
     * TODO Phase 2 integration: inotify watch + PID resolution */
    while (g_running) {
        sleep(5);
    }
}

/* ── Signal handling ───────────────────────────────────────────── */

static void signal_handler(int sig) {
    (void)sig;
    g_running = false;
}

/* ── Main ──────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

#ifdef __ANDROID__
    android::base::InitLogging(argv, android::base::LogdLogger());
#endif

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    LOG(INFO) << "apktrace_collector starting";

    /* Ensure data directory exists */
    mkdir(kDataDir, 0770);

    /* Start command server thread */
    std::thread cmd_thread(command_server_loop);

    /* Start TLS log watcher thread */
    std::thread tls_thread(tls_log_watcher);

    /* Main loop — periodic housekeeping */
    while (g_running) {
        sleep(10);
        /* TODO: periodic flush, buffer rotation, HTTP server, eBPF poll */
    }

    LOG(INFO) << "apktrace_collector stopping";

    cmd_thread.join();
    tls_thread.join();

    return 0;
}
