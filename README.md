# AOSP Patches

This repo contains the Pixel 8a (`akita`) AOSP patch set plus helper scripts
for local builds.

## Standard AOSP Build

For the normal `aosp_akita` build, use the generated fastboot manifest instead
of manually flashing partitions:

```bash
source build/envsetup.sh
lunch aosp_akita-trunk_staging-userdebug
m -j$(nproc)

/path/to/aosp-patches/flash-aosp.sh --serial <serial> --slot a
```

`flash-aosp.sh` expects the standard build output under:

```bash
~/aosp/out/target/product/akita
```

By default it:

- uses `ANDROID_PRODUCT_OUT` with `fastboot flashall`
- prefers the host-built fastboot binary from the AOSP tree
- reboots from `adb` to bootloader when possible
- wipes `userdata` and `metadata` unless `--no-wipe` is passed

Run `flash-aosp.sh --help` for the available options.

## Research Build

The existing research/apktrace build flow is unchanged by the standard AOSP
flashing wrapper added here.

- `apply.sh` still applies the research patch set
- `flash-research.sh` is still the separate research flashing script
- `aosp-instrumentation-plan.md` still documents the research product

This documentation update only adds the standard `aosp_akita` flashing path.
