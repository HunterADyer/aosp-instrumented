# Building the apktrace kernel module

## As built-in (recommended for GKI kernels)

GKI kernels don't export tracepoint symbols to loadable modules.
Build apktrace as a built-in (`CONFIG_APKTRACE=y`).

1. Clone kernel source:
   ```
   git clone --single-branch -b android-gs-shusky-6.1-android16 --depth 1 \
       https://android.googlesource.com/kernel/common
   ```

2. Copy driver files:
   ```
   mkdir -p common/drivers/apktrace
   cp apktrace-module/apktrace.c common/drivers/apktrace/
   cp Kconfig common/drivers/apktrace/
   cp Makefile.intree common/drivers/apktrace/Makefile
   ```

3. Add to parent Kconfig/Makefile:
   ```
   echo 'source "drivers/apktrace/Kconfig"' >> common/drivers/Kconfig  # before endmenu
   echo 'obj-$(CONFIG_APKTRACE) += apktrace/' >> common/drivers/Makefile
   ```

4. Configure and build:
   ```
   zcat <device-config.gz> > .config
   scripts/config --enable CONFIG_APKTRACE
   scripts/config --disable CONFIG_DEBUG_INFO_BTF
   make ARCH=arm64 LLVM=1 vmlinux -j$(nproc)
   ```

5. The vmlinux contains apktrace. Flash via boot.img rebuild.

## Usage on device

```bash
# Add a UID to trace (Android UID = app package)
echo "+10123" > /proc/apktrace_ctl

# Read trace events (blocking, supports poll)
cat /proc/apktrace

# Remove UID
echo "-10123" > /proc/apktrace_ctl

# Clear all
echo "clear" > /proc/apktrace_ctl

# List traced UIDs
cat /proc/apktrace_ctl
```

Events are JSON lines:
```json
{"ts":1234567890,"c":"sys","e":"openat","pid":1234,"tid":1234,"uid":10123,"a0":18446744073709551516,"a1":140727488355104}
{"ts":1234567891,"c":"sched","e":"fork","pid":1234,"child_pid":1235,"uid":10123}
{"ts":1234567892,"c":"sched","e":"exec","pid":1235,"uid":10123,"file":"/system/bin/app_process64"}
```
