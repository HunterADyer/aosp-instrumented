#!/bin/bash
# flash-aosp.sh — Flash the standard aosp_akita build via fastboot flashall.
#
# Intended for the normal AOSP Pixel 8a build output, for example:
#   lunch aosp_akita-trunk_staging-userdebug
#   m -j$(nproc)
#
# This uses the generated fastboot manifest from ANDROID_PRODUCT_OUT instead of
# manually flashing partitions. On modern Pixels that matters because the
# manifest-driven flow handles slot activation, rebooting into userspace
# fastboot, update-super, and vbmeta application in the expected order.

set -euo pipefail

SERIAL="${ANDROID_SERIAL:-}"
SLOT="a"
WIPE=1
AOSP_OUT="${AOSP_OUT:-$HOME/aosp/out/target/product/akita}"
FASTBOOT_BIN="${FASTBOOT:-}"

HOST_FASTBOOT="$HOME/aosp/out/host/linux-x86/bin/fastboot"
SDK_FASTBOOT="$HOME/Android/Sdk/platform-tools/fastboot"

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --serial SERIAL       Device serial to target
  --slot a|b            Slot to flash and mark active (default: a)
  --no-wipe             Skip userdata/metadata wipe
  --product-out PATH    Product output directory (default: $AOSP_OUT)
  --fastboot PATH       Fastboot binary to use
  -h, --help            Show this help

Examples:
  $(basename "$0")
  $(basename "$0") --serial 45081JEKB09562 --slot b
  $(basename "$0") --product-out ~/aosp/out/target/product/akita --no-wipe
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --serial)
            SERIAL="$2"
            shift 2
            ;;
        --slot)
            SLOT="$2"
            shift 2
            ;;
        --no-wipe)
            WIPE=0
            shift
            ;;
        --product-out)
            AOSP_OUT="$2"
            shift 2
            ;;
        --fastboot)
            FASTBOOT_BIN="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ "$SLOT" != "a" ] && [ "$SLOT" != "b" ]; then
    echo "ERROR: --slot must be 'a' or 'b'" >&2
    exit 1
fi

choose_fastboot() {
    if [ -n "$FASTBOOT_BIN" ]; then
        return
    fi
    if [ -x "$HOST_FASTBOOT" ]; then
        FASTBOOT_BIN="$HOST_FASTBOOT"
        return
    fi
    if [ -x "$SDK_FASTBOOT" ]; then
        FASTBOOT_BIN="$SDK_FASTBOOT"
        return
    fi

    echo "ERROR: fastboot not found." >&2
    echo "Tried:" >&2
    echo "  $HOST_FASTBOOT" >&2
    echo "  $SDK_FASTBOOT" >&2
    echo "Set FASTBOOT=/path/to/fastboot or pass --fastboot PATH." >&2
    exit 1
}

fb() {
    if [ -n "$SERIAL" ]; then
        "$FASTBOOT_BIN" -s "$SERIAL" "$@"
    else
        "$FASTBOOT_BIN" "$@"
    fi
}

adb_cmd() {
    if [ -n "$SERIAL" ]; then
        adb -s "$SERIAL" "$@"
    else
        adb "$@"
    fi
}

wait_for_fastboot() {
    local attempt out
    for attempt in $(seq 1 30); do
        out="$(fb getvar product 2>&1 || true)"
        if printf '%s\n' "$out" | grep -q "product:"; then
            printf '%s\n' "$out"
            return 0
        fi
        sleep 1
    done
    return 1
}

choose_fastboot

if [ ! -f "$AOSP_OUT/fastboot-info.txt" ]; then
    echo "ERROR: $AOSP_OUT/fastboot-info.txt not found" >&2
    exit 1
fi

if [ ! -f "$AOSP_OUT/android-info.txt" ]; then
    echo "ERROR: $AOSP_OUT/android-info.txt not found" >&2
    exit 1
fi

for img in boot.img init_boot.img vbmeta.img system.img vendor.img product.img; do
    if [ ! -f "$AOSP_OUT/$img" ]; then
        echo "ERROR: $AOSP_OUT/$img not found" >&2
        exit 1
    fi
done

echo "=== AOSP Akita Flash ==="
echo "Serial:      ${SERIAL:-<auto>}"
echo "Fastboot:    $FASTBOOT_BIN"
echo "Product out: $AOSP_OUT"
echo "Target slot: $SLOT"
if [ "$WIPE" -eq 1 ]; then
    echo "Wipe data:   yes"
else
    echo "Wipe data:   no"
    echo "Note: skipping wipe can leave stale data after major system changes."
fi
echo ""

if adb_cmd get-state 2>/dev/null | grep -qx "device"; then
    echo "ADB device detected. Rebooting to bootloader..."
    adb_cmd reboot bootloader
fi

echo "Waiting for fastboot..."
PRODUCT_INFO="$(wait_for_fastboot || true)"
if [ -z "${PRODUCT_INFO:-}" ]; then
    echo "ERROR: device not detected in fastboot mode." >&2
    echo "If needed, reboot manually with: adb reboot bootloader" >&2
    exit 1
fi

PRODUCT="$(printf '%s\n' "$PRODUCT_INFO" | awk '/product:/ {print $2; exit}')"
if [ "$PRODUCT" != "akita" ]; then
    echo "ERROR: connected device is '$PRODUCT', expected 'akita'" >&2
    exit 1
fi

CURRENT_SLOT="$(fb getvar current-slot 2>&1 | awk '/current-slot:/ {print $2; exit}' || true)"
if [ -n "${CURRENT_SLOT:-}" ]; then
    echo "Current slot: $CURRENT_SLOT"
fi

echo "Using generated manifest:"
echo "  $AOSP_OUT/fastboot-info.txt"
echo ""

export ANDROID_PRODUCT_OUT="$AOSP_OUT"

FLASHALL_ARGS=(flashall --slot "$SLOT")
if [ "$WIPE" -eq 1 ]; then
    FLASHALL_ARGS+=(-w)
fi

fb "${FLASHALL_ARGS[@]}"

echo ""
echo "Flash complete. Wait for Android to boot, then verify with:"
if [ -n "$SERIAL" ]; then
    echo "  adb -s $SERIAL wait-for-device"
    echo "  adb -s $SERIAL shell getprop sys.boot_completed"
else
    echo "  adb wait-for-device"
    echo "  adb shell getprop sys.boot_completed"
fi
