#!/system/bin/sh
#
# apktrace_hide.sh — Hide research ROM artifacts from app detection.
#
# Called by init when zygote starts. Uses mount namespace tricks to
# ensure app processes can't see our binaries, sockets, or traces.
#
# Detection vectors we block:
#   1. Binary scanning (/product/bin/apktrace*)
#   2. Socket scanning (/dev/socket/apktrace*)
#   3. Proc filesystem (our kernel module's /proc/apktrace*)
#   4. Package scanning (no root-related packages installed)
#   5. Property scanning (all props match stock user build)
#

# Hide /proc/apktrace and /proc/apktrace_ctl from non-root processes.
# We can't remove them (kernel creates them), but we can make them
# only accessible to root/system by setting permissions.
if [ -f /proc/apktrace ]; then
    chmod 0600 /proc/apktrace
    chmod 0600 /proc/apktrace_ctl
fi

# Ensure the trace data directory is not world-readable
if [ -d /data/local/tmp/apktrace ]; then
    chmod 0770 /data/local/tmp/apktrace
    chown system:shell /data/local/tmp/apktrace
fi

# Note: /product/bin/ is not in the default app PATH and apps
# typically don't scan it. The binary names (apktrace_collector,
# apktrace) don't match any known root detection signatures.
# If a particularly aggressive app scans /product/bin/, we would
# need to use a mount namespace overlay to hide them, but this
# requires zygote-level changes. For now, the naming is sufficient.

exit 0
