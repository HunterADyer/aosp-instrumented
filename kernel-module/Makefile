# Build against the Pixel 8a kernel source tree
# Usage:
#   make KERNEL_SRC=../common ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
#
# Or with AOSP prebuilt clang:
#   make KERNEL_SRC=../common ARCH=arm64 \
#     CROSS_COMPILE=aarch64-linux-gnu- \
#     CC=../../prebuilts/clang/host/linux-x86/clang-r563880c/bin/clang \
#     LLVM=1

obj-m += apktrace.o

KERNEL_SRC ?= ../common

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean
