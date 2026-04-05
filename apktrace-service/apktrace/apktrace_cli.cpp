/*
 * apktrace — CLI tool for controlling the apktrace_collector daemon.
 *
 * Usage:
 *   apktrace start <pkg> [--categories=tls,fs,binder,tee]
 *   apktrace stop <pkg>
 *   apktrace dump <pkg>
 *   apktrace status
 *   apktrace flush
 *   apktrace keylog {start|stop}
 *   apktrace pcap {start|stop}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static constexpr const char *kSocketPath = "/dev/socket/apktrace";

static int send_command(const char *cmd) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, kSocketPath, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to connect to apktrace_collector. Is the service running?\n");
        fprintf(stderr, "Start it with: setprop persist.apktrace.enabled 1\n");
        close(fd);
        return 1;
    }

    write(fd, cmd, strlen(cmd));

    /* Read response */
    char buf[65536];
    ssize_t total = 0;
    while (1) {
        ssize_t n = read(fd, buf + total, sizeof(buf) - total - 1);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = '\0';

    printf("%s", buf);
    close(fd);
    return 0;
}

static void usage() {
    fprintf(stderr,
        "Usage: apktrace <command> [args]\n"
        "\n"
        "Commands:\n"
        "  start <pkg> [--categories=tls,fs,binder,tee,lifecycle]\n"
        "  stop <pkg>\n"
        "  dump <pkg>\n"
        "  status\n"
        "  flush\n"
        "  keylog {start|stop}\n"
        "  pcap {start|stop}\n"
    );
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    /* Handle keylog and pcap locally via system properties */
    if (strcmp(argv[1], "keylog") == 0) {
        if (argc < 3) { usage(); return 1; }
#ifdef __ANDROID__
        const char *val = strcmp(argv[2], "start") == 0 ? "1" : "0";
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "setprop persist.apktrace.tls_keylog %s", val);
        return system(cmd);
#else
        fprintf(stderr, "keylog control only works on Android\n");
        return 1;
#endif
    }

    if (strcmp(argv[1], "pcap") == 0) {
        if (argc < 3) { usage(); return 1; }
        if (strcmp(argv[2], "start") == 0) {
            return system("tcpdump -i any -w /data/local/tmp/apktrace/capture.pcap &");
        } else {
            return system("pkill tcpdump");
        }
    }

    /* Build command string from args */
    char cmd[4096] = {0};
    int offset = 0;
    for (int i = 1; i < argc && offset < (int)sizeof(cmd) - 2; i++) {
        if (i > 1) cmd[offset++] = ' ';
        int n = snprintf(cmd + offset, sizeof(cmd) - offset, "%s", argv[i]);
        offset += n;
    }

    return send_command(cmd);
}
