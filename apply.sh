#!/bin/bash
# apply.sh — Apply all instrumentation patches to an AOSP tree.
#
# Usage:
#   cd /path/to/aosp
#   /path/to/aosp-patches/apply.sh
#
# Prerequisites:
#   - AOSP tree synced at android-16.0.0_r4
#   - Pixel 8a device trees synced (device/google/akita, zuma, gs-common, etc.)
#   - Run from the AOSP root directory

set -e
PATCH_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f build/envsetup.sh ]; then
    echo "ERROR: Run this from the AOSP root directory"
    exit 1
fi

echo "Applying AOSP instrumentation patches from $PATCH_DIR"
echo ""

# Phase 2: BoringSSL TLS plaintext capture
echo "[1/7] BoringSSL: new files (apktrace_tls.cc, apktrace_tls.h)"
cd external/boringssl
git apply "$PATCH_DIR/01-boringssl-tls-capture-new-files.patch"
echo "[2/7] BoringSSL: hooks in ssl_lib.cc + sources.bp"
git apply "$PATCH_DIR/02-boringssl-tls-capture-hooks.patch"
cd ../..

# Phase 1: Research product definition
echo "[3/7] Akita: AndroidProducts.mk update"
cd device/google/akita
git apply "$PATCH_DIR/03-akita-product-def-mod.patch"
echo "[4/7] Akita: aosp_akita_research.mk (new product)"
cp "$PATCH_DIR/../04-akita-research-product.patch" /tmp/_akita_research.patch
git apply /tmp/_akita_research.patch || cp "$PATCH_DIR/aosp_akita_research.mk" .
cd ../../..

# SEPolicy fixes (main branch → android-16 compatibility)
echo "[5/7] gs-common: SEPolicy neverallow fixes"
cd device/google/gs-common
git apply "$PATCH_DIR/05-gs-common-sepolicy-fixes.patch"
cd ../../..

echo "[6/7] zuma-sepolicy: SEPolicy neverallow fixes"
cd device/google/zuma-sepolicy
git apply "$PATCH_DIR/06-zuma-sepolicy-fixes.patch"
cd ../..

echo "[7/7] Akita: PRODUCT_SYSTEM_PROPERTIES fix"
cd device/google/akita
git apply "$PATCH_DIR/07-akita-property-fix.patch"
cd ../../..

echo ""
echo "All patches applied. Build with:"
echo "  source build/envsetup.sh"
echo "  lunch aosp_akita_research-trunk_staging-userdebug"
echo "  m -j\$(nproc)"
