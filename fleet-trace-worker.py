"""
Trace pipeline worker — one thread per rooted Pixel 8a.

Workflow per trace job:
  1. Claim from trace_jobs
  2. Sideload APK from NAS path
  3. Start traces (kernel: eBPF/ftrace; usermode: Frida)
  4. Capture serial debug output (UART over USB-C)
  5. Launch app, wait TRACE_DURATION_SEC
  6. Stop traces, pull trace data
  7. Atomic commit to NAS: /mnt/alexandria/apk-research/traces/{pkg}/vc{vc}/
  8. Profile wipe lite
  9. Mark job completed, insert trace_results row

Tracing backend is pluggable via TracingBackend ABC.  Worker tries
FridaBackend → GadgetBackend → StraceBackend in order.
"""

from __future__ import annotations

import glob as _glob
import hashlib
import json
import logging
import os
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from abc import ABC, abstractmethod
from typing import List, Optional

from . import adb as fleet_adb
from . import db as fleet_db
from .config import (
    FLEET_DB_PATH,
    TRACE_DURATION_SEC,
    TRACE_NAS_DIR,
    TRACE_SERIAL_BAUD,
    TRACE_STAGING_DIR,
)

log = logging.getLogger("fleet.trace_worker")

TRACE_ARTIFACT_SUBDIRS = ("rom", "frida", "ebpf", "strace", "ftrace", "serial")


# ---------------------------------------------------------------------------
# Tracing backend ABC + implementations
# ---------------------------------------------------------------------------

class TracingBackend(ABC):
    """Abstract base for trace capture backends."""

    name: str = "base"

    @abstractmethod
    def start(self, serial: str, package: str,
              staging_dir: str) -> bool:
        """Start tracing. Returns True if successfully started."""

    @abstractmethod
    def stop(self, serial: str, package: str,
             staging_dir: str) -> bool:
        """Stop tracing and pull data to staging_dir. Returns True on success."""

    @abstractmethod
    def is_available(self, serial: str) -> bool:
        """Check if this backend can run on the given device."""

    def requires_running_process(self) -> bool:
        return False


FRIDA_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "frida_script.js")
FRIDA_SERVER_DEVICE_PATH = "/data/local/tmp/frida-server"


def _ensure_frida_server(serial: str) -> bool:
    """Make sure frida-server is running on the device. Returns True if alive."""
    rc, out, _ = fleet_adb.adb(
        ["shell", "su", "-c", "ps -A | grep frida-server"],
        serial=serial, timeout=10,
    )
    if rc == 0 and "frida-server" in (out or ""):
        return True

    # Check binary exists on device
    rc, _, _ = fleet_adb.adb(
        ["shell", "su", "-c", f"test -x {FRIDA_SERVER_DEVICE_PATH} && echo ok"],
        serial=serial, timeout=5,
    )
    if rc != 0:
        log.warning("[%s] frida-server binary missing at %s",
                    serial, FRIDA_SERVER_DEVICE_PATH)
        return False

    # Start it
    log.info("[%s] Starting frida-server...", serial)
    fleet_adb.adb(
        ["shell", "su", "-c",
         f"nohup {FRIDA_SERVER_DEVICE_PATH} -D > /dev/null 2>&1 &"],
        serial=serial, timeout=10,
    )
    time.sleep(2)

    rc, out, _ = fleet_adb.adb(
        ["shell", "su", "-c", "ps -A | grep frida-server"],
        serial=serial, timeout=10,
    )
    alive = rc == 0 and "frida-server" in (out or "")
    if alive:
        log.info("[%s] frida-server started", serial)
    else:
        log.error("[%s] frida-server failed to start", serial)
    return alive


class FridaBackend(TracingBackend):
    """Script-based Frida tracing — hooks Java + native APIs via custom script."""

    name = "frida"

    def is_available(self, serial: str) -> bool:
        return _ensure_frida_server(serial)

    def start(self, serial: str, package: str,
              staging_dir: str) -> bool:
        frida_dir = os.path.join(staging_dir, "frida")
        os.makedirs(frida_dir, exist_ok=True)

        if not os.path.exists(FRIDA_SCRIPT_PATH):
            log.error("Frida script not found: %s", FRIDA_SCRIPT_PATH)
            return False

        trace_log_path = os.path.join(frida_dir, "trace.jsonl")

        try:
            import frida

            device = frida.get_device(serial, timeout=10)

            with open(FRIDA_SCRIPT_PATH) as f:
                script_src = f.read()

            self._trace_fh = open(trace_log_path, "w")

            def on_message(message, data):
                if message["type"] == "send":
                    self._trace_fh.write(message["payload"] + "\n")
                elif message["type"] == "error":
                    self._trace_fh.write(
                        json.dumps({"ts": time.time() * 1000, "c": "error",
                                    "e": "frida_error",
                                    "desc": message.get("description", "")}) + "\n"
                    )

            # Try spawn first (hooks before any code runs).
            # Falls back to launch + attach for apps that break spawn
            # (custom Application classes, complex init).
            pid = None
            spawned = False
            try:
                pid = device.spawn([package])
                spawned = True
                log.info("[%s] Frida spawned %s (pid %d)", serial, package, pid)
            except Exception as spawn_err:
                log.info("[%s] Frida spawn failed (%s), using launch+attach",
                         serial, type(spawn_err).__name__)
                # Kill any leftover process, launch fresh, attach
                fleet_adb.adb(["shell", "am", "force-stop", package],
                              serial=serial, timeout=5)
                time.sleep(1)
                fleet_adb.adb(
                    ["shell", "am", "start", "-n",
                     f"{package}/{package}.HomeActivity"],
                    serial=serial, timeout=10)
                # Also try generic launcher
                fleet_adb.adb(
                    ["shell", "monkey", "-p", package,
                     "-c", "android.intent.category.LAUNCHER", "1"],
                    serial=serial, timeout=10)
                time.sleep(3)
                # Find PID
                rc, out, _ = fleet_adb.adb(
                    ["shell", "pidof", package], serial=serial, timeout=5)
                if rc == 0 and out.strip():
                    pid = int(out.strip().split()[0])
                    log.info("[%s] Attaching to running %s (pid %d)",
                             serial, package, pid)
                else:
                    raise RuntimeError(f"App {package} not running after launch")

            session = device.attach(pid)
            script = session.create_script(script_src, runtime="v8")
            script.on("message", on_message)
            script.load()

            if spawned:
                device.resume(pid)

            self._device = device
            self._session = session
            self._script = script
            self._pid = pid
            log.info("[%s] Frida ready on %s (pid %d, spawned=%s)",
                     serial, package, pid, spawned)
            return True

        except Exception:
            log.exception("[%s] Failed to start Frida for %s", serial, package)
            for attr in ("_script", "_session"):
                obj = getattr(self, attr, None)
                if obj:
                    try:
                        obj.detach() if hasattr(obj, "detach") else None
                    except Exception:
                        pass
                    setattr(self, attr, None)
            fh = getattr(self, "_trace_fh", None)
            if fh:
                fh.close()
                self._trace_fh = None
            return False

    def stop(self, serial: str, package: str,
             staging_dir: str) -> bool:
        stopped = True
        try:
            script = getattr(self, "_script", None)
            if script:
                try:
                    script.unload()
                except Exception:
                    pass
            session = getattr(self, "_session", None)
            if session:
                try:
                    session.detach()
                except Exception:
                    pass
        except Exception:
            stopped = False
            log.exception("[%s] Failed to stop Frida for %s", serial, package)
        finally:
            self._script = None
            self._session = None
            self._device = None
            self._pid = None
            fh = getattr(self, "_trace_fh", None)
            if fh:
                fh.close()
                self._trace_fh = None
        return stopped


class EbpfBackend(TracingBackend):
    """eBPF/tracefs-based kernel tracing — raw syscalls, binder, scheduling, network, signals."""

    name = "ebpf"

    # PID-filterable events (set_event_pid works for these)
    PID_EVENTS = [
        "binder/binder_transaction",
        "binder/binder_ioctl",
        "sched/sched_process_exec",
        "sched/sched_process_fork",
        "sched/sched_process_exit",
        "net/net_dev_xmit",
        "signal/signal_generate",
        "task/task_newtask",
    ]

    # Interesting syscall numbers (arm64) to filter via event filter.
    # set_event_pid does NOT work for raw_syscalls on many Android kernels,
    # so we filter by syscall ID instead and post-filter by PID/comm.
    SYSCALL_FILTER_NRS = [
        56,   # openat
        57,   # close
        63,   # read
        64,   # write
        198,  # socket
        200,  # bind
        203,  # connect
        206,  # sendto
        207,  # recvfrom
        221,  # execve
        222,  # mmap
        226,  # mprotect
        220,  # clone
        291,  # statx
    ]

    TRACEFS = "/sys/kernel/tracing"

    def is_available(self, serial: str) -> bool:
        rc, out, _ = fleet_adb.adb(
            ["shell", "su", "-c",
             f"test -d {self.TRACEFS}/events/raw_syscalls && echo ok"],
            serial=serial, timeout=5,
        )
        return rc == 0 and "ok" in (out or "")

    def _trace_cmd(self, serial: str, cmd: str, timeout: int = 5) -> bool:
        """Run a single su -c command on the tracefs. Returns success."""
        rc, _, err = fleet_adb.adb(
            ["shell", "su", "-c", cmd], serial=serial, timeout=timeout,
        )
        return rc == 0

    def start(self, serial: str, package: str,
              staging_dir: str) -> bool:
        ebpf_dir = os.path.join(staging_dir, "ebpf")
        os.makedirs(ebpf_dir, exist_ok=True)

        T = self.TRACEFS

        # Reset tracing state
        self._trace_cmd(serial, f"echo 0 > {T}/tracing_on")
        self._trace_cmd(serial, f"echo > {T}/trace")
        self._trace_cmd(serial, f"echo 16384 > {T}/buffer_size_kb")

        # Get PID if app is already running
        rc, out, _ = fleet_adb.adb(
            ["shell", "pidof", package], serial=serial, timeout=5
        )
        pids = out.strip().split() if rc == 0 and out.strip() else []

        # Don't use set_event_pid — it acts as a global gate that also blocks
        # raw_syscalls events even when they have their own filter.
        # Instead, we trace system-wide and post-filter by PID/comm.
        self._trace_cmd(serial, f"echo > {T}/set_event_pid")
        self._trace_cmd(serial, f"echo 1 > {T}/options/event-fork")
        self._filtered = False

        # Enable PID-filterable events
        for event in self.PID_EVENTS:
            self._trace_cmd(serial,
                f"echo 1 > {T}/events/{event}/enable 2>/dev/null || true")

        # Enable raw_syscalls with syscall ID filter (bypasses PID filter issue).
        # Use push to avoid shell quoting issues with su -c.
        syscall_filter = " || ".join(f"id == {nr}" for nr in self.SYSCALL_FILTER_NRS)
        filter_tmp = os.path.join(tempfile.gettempdir(), "_trace_filter.txt")
        with open(filter_tmp, "w") as ff:
            ff.write(syscall_filter + "\n")
        fleet_adb.adb(["push", filter_tmp, "/data/local/tmp/_trace_filter.txt"],
                       serial=serial, timeout=5)
        os.unlink(filter_tmp)
        self._trace_cmd(serial,
            f"cat /data/local/tmp/_trace_filter.txt > {T}/events/raw_syscalls/sys_enter/filter "
            f"&& rm /data/local/tmp/_trace_filter.txt")
        self._trace_cmd(serial,
            f"echo 1 > {T}/events/raw_syscalls/sys_enter/enable")

        # Start tracing
        self._trace_cmd(serial, f"echo 1 > {T}/tracing_on")

        self._staging_ebpf_dir = ebpf_dir
        self._package = package
        log.info("[%s] tracefs started (raw_syscalls[%d NRs] + %d events, pid_filter=%s)",
                 serial, len(self.SYSCALL_FILTER_NRS), len(self.PID_EVENTS),
                 ",".join(pids) if pids else "pending")
        return True

    def _update_pid_filter(self, serial: str, package: str) -> None:
        """Record PIDs for post-processing filter. Logged for reference."""
        rc, out, _ = fleet_adb.adb(
            ["shell", "pidof", package], serial=serial, timeout=5
        )
        if rc == 0 and out.strip():
            pids = out.strip().split()
            self._target_pids = set(pids)
            log.info("[%s] Target PIDs for post-filter: %s", serial, " ".join(pids))

    def requires_running_process(self) -> bool:
        return False

    def stop(self, serial: str, package: str,
             staging_dir: str) -> bool:
        ebpf_dir = getattr(self, "_staging_ebpf_dir", None) or \
                   os.path.join(staging_dir, "ebpf")
        os.makedirs(ebpf_dir, exist_ok=True)
        T = self.TRACEFS

        self._trace_cmd(serial, f"echo 0 > {T}/tracing_on")

        # Pull trace data
        device_trace = "/data/local/tmp/ebpf_trace.dat"
        self._trace_cmd(serial, f"cat {T}/trace > {device_trace}", timeout=30)

        raw_trace = os.path.join(ebpf_dir, "trace_raw.dat")
        local_trace = os.path.join(ebpf_dir, "trace.dat")
        pulled = fleet_adb.pull_file(serial, device_trace, raw_trace)

        # Post-filter by target PIDs / comm name
        if pulled and os.path.exists(raw_trace):
            target_pids = getattr(self, "_target_pids", set())
            pkg = getattr(self, "_package", package) or package
            # Extract comm prefix from package (Android truncates to ~15 chars)
            comm_prefixes = set()
            if pkg:
                parts = pkg.split(".")
                # Android uses last component or truncated package
                comm_prefixes.add(pkg[-15:])  # truncated full package
                if len(parts) >= 2:
                    comm_prefixes.add(parts[-1][:15])  # last component
            try:
                kept = 0
                with open(raw_trace) as rf, open(local_trace, "w") as wf:
                    for line in rf:
                        if line.startswith("#"):
                            wf.write(line)
                            continue
                        if not line.strip():
                            continue
                        # Check if any target PID appears in the line
                        keep = False
                        if target_pids:
                            for pid in target_pids:
                                if f"-{pid} " in line or f"-{pid}\t" in line:
                                    keep = True
                                    break
                        # Also check comm name prefix
                        if not keep and comm_prefixes:
                            for prefix in comm_prefixes:
                                if prefix in line:
                                    keep = True
                                    break
                        if keep:
                            wf.write(line)
                            kept += 1
                log.info("[%s] Post-filtered trace: %d events (from raw)", serial, kept)
            except Exception:
                log.exception("[%s] Post-filter failed, keeping raw trace", serial)
                import shutil
                shutil.copy2(raw_trace, local_trace)

        # Clean up device state
        self._trace_cmd(serial,
            f"echo 0 > {T}/events/raw_syscalls/sys_enter/enable")
        self._trace_cmd(serial,
            f"echo 0 > {T}/events/raw_syscalls/sys_enter/filter 2>/dev/null || true")
        for event in self.PID_EVENTS:
            self._trace_cmd(serial,
                f"echo 0 > {T}/events/{event}/enable 2>/dev/null || true")
        self._trace_cmd(serial, f"echo > {T}/set_event_pid")
        self._trace_cmd(serial, f"echo 0 > {T}/options/event-fork")
        self._trace_cmd(serial, f"echo > {T}/trace")
        self._trace_cmd(serial, f"rm -f {device_trace}")

        if not pulled:
            log.warning("[%s] Failed to pull tracefs data", serial)
        else:
            size = os.path.getsize(local_trace) if os.path.exists(local_trace) else 0
            log.info("[%s] Pulled tracefs data: %.1f KB", serial, size / 1024)

        self._staging_ebpf_dir = None
        self._filtered = False
        return pulled


class StraceBackend(TracingBackend):
    """Ptrace-based tracing using strace — fallback for anti-Frida apps."""

    name = "strace"

    def is_available(self, serial: str) -> bool:
        rc, _, _ = fleet_adb.adb(
            ["shell", "which", "strace"], serial=serial, timeout=5
        )
        return rc == 0

    def requires_running_process(self) -> bool:
        return True

    def start(self, serial: str, package: str,
              staging_dir: str) -> bool:
        strace_dir = os.path.join(staging_dir, "strace")
        os.makedirs(strace_dir, exist_ok=True)

        # Get PID of target app
        rc, out, _ = fleet_adb.adb(
            ["shell", "pidof", package], serial=serial, timeout=5
        )
        if rc != 0 or not out.strip():
            log.warning("[%s] Could not find PID for %s", serial, package)
            return False

        pid = out.strip().split()[0]
        if not pid.isdigit():
            log.warning("[%s] Unexpected PID output for %s: %r", serial, package, out)
            return False
        self._strace_device_path = (
            f"/data/local/tmp/strace_{os.path.basename(staging_dir)}.log"
        )

        # Start strace on device in background
        start_cmd = (
            f"nohup strace -f -p {pid} -o {shlex.quote(self._strace_device_path)} "
            "> /dev/null 2>&1 & echo $!"
        )
        rc, out, err = fleet_adb.adb(["shell", start_cmd], serial=serial, timeout=10)
        if rc != 0 or not out.strip():
            log.warning("[%s] Failed to start strace for %s: %s", serial, package, err)
            return False
        self._strace_pid = out.strip().splitlines()[-1].strip()
        if not self._strace_pid.isdigit():
            log.warning("[%s] Unexpected strace PID for %s: %r",
                        serial, package, out)
            return False

        # Verify strace actually attached — the backgrounded command always
        # returns rc=0 so we need to check the process is alive on-device.
        time.sleep(1)
        rc, _, _ = fleet_adb.adb(
            ["shell", "kill", "-0", self._strace_pid], serial=serial, timeout=5
        )
        if rc != 0:
            log.warning("[%s] strace failed to attach to %s (pid %s)",
                        serial, package, pid)
            return False
        return True

    def stop(self, serial: str, package: str,
             staging_dir: str) -> bool:
        strace_pid = getattr(self, "_strace_pid", None)
        if strace_pid:
            rc, _, err = fleet_adb.adb(
                ["shell", "kill", "-TERM", strace_pid],
                serial=serial, timeout=5
            )
            if rc != 0:
                log.warning("[%s] Failed to stop strace pid %s for %s: %s",
                            serial, strace_pid, package, err)
            time.sleep(1)

        # Pull strace output
        strace_dir = os.path.join(staging_dir, "strace")
        os.makedirs(strace_dir, exist_ok=True)
        local_path = os.path.join(strace_dir, "strace.log")

        pulled = False
        device_path = getattr(self, "_strace_device_path", None)
        if device_path:
            pulled = fleet_adb.pull_file(serial, device_path, local_path)
            if pulled:
                fleet_adb.adb(
                    ["shell", "rm", "-f", device_path],
                    serial=serial, timeout=5
                )
            else:
                log.warning("[%s] Failed to pull strace log, leaving on device: %s",
                            serial, device_path)
        self._strace_pid = None
        self._strace_device_path = None
        return pulled


class RomTraceBackend(TracingBackend):
    """ROM-level instrumentation via apktrace system service on research ROM."""

    name = "rom"

    def is_available(self, serial: str) -> bool:
        rc, out, _ = fleet_adb.adb(
            ["shell", "which", "apktrace"], serial=serial, timeout=5,
        )
        return rc == 0 and "apktrace" in (out or "")

    def start(self, serial: str, package: str,
              staging_dir: str) -> bool:
        # Enable tracing globally if not already on
        fleet_adb.adb(
            ["shell", "setprop", "persist.apktrace.enabled", "1"],
            serial=serial, timeout=5,
        )
        fleet_adb.adb(
            ["shell", "setprop", "persist.apktrace.tls_plaintext", "1"],
            serial=serial, timeout=5,
        )

        # Start tracing this package (all categories)
        rc, out, err = fleet_adb.adb(
            ["shell", "apktrace", "start", package],
            serial=serial, timeout=10,
        )
        if rc != 0:
            log.warning("[%s] apktrace start failed: %s", serial, err)
            return False

        # Also load the kernel module if present and not loaded
        fleet_adb.adb(
            ["shell", "su", "-c",
             "lsmod | grep -q apktrace || "
             "(test -f /data/local/tmp/apktrace.ko && "
             "insmod /data/local/tmp/apktrace.ko)"],
            serial=serial, timeout=10,
        )

        # Add the app's UID to the kernel module's traced UIDs
        rc, out, _ = fleet_adb.adb(
            ["shell", "pm", "list", "packages", "-U", package],
            serial=serial, timeout=10,
        )
        if rc == 0 and "uid:" in out:
            import re
            m = re.search(r'uid:(\d+)', out)
            if m:
                uid = m.group(1)
                fleet_adb.adb(
                    ["shell", "su", "-c",
                     f"echo +{uid} > /proc/apktrace_ctl"],
                    serial=serial, timeout=5,
                )
                log.info("[%s] apktrace: tracing %s (uid %s)", serial, package, uid)

        log.info("[%s] ROM trace started for %s", serial, package)
        return True

    def stop(self, serial: str, package: str,
             staging_dir: str) -> bool:
        rom_dir = os.path.join(staging_dir, "rom")
        os.makedirs(rom_dir, exist_ok=True)

        # Flush traces
        fleet_adb.adb(
            ["shell", "apktrace", "flush"], serial=serial, timeout=10,
        )

        # Pull apktrace service data
        rc, _, _ = fleet_adb.adb(
            ["shell", "test", "-d", f"/data/local/tmp/apktrace/{package}"],
            serial=serial, timeout=5,
        )
        if rc == 0:
            # Pull the whole package trace dir
            fleet_adb.adb(
                ["pull", f"/data/local/tmp/apktrace/{package}/", rom_dir],
                serial=serial, timeout=60,
            )

        # Pull TLS plaintext log (shared across packages, filter later)
        tls_log = "/data/local/tmp/apktrace/tls_plaintext.jsonl"
        rc, _, _ = fleet_adb.adb(
            ["shell", "test", "-f", tls_log], serial=serial, timeout=5,
        )
        if rc == 0:
            fleet_adb.pull_file(serial, tls_log,
                               os.path.join(rom_dir, "tls_plaintext.jsonl"))

        # Pull kernel module trace data
        fleet_adb.adb(
            ["shell", "su", "-c",
             f"cat /proc/apktrace > /data/local/tmp/apktrace/{package}/kernel.jsonl"],
            serial=serial, timeout=30,
        )
        fleet_adb.pull_file(serial,
                           f"/data/local/tmp/apktrace/{package}/kernel.jsonl",
                           os.path.join(rom_dir, "kernel.jsonl"))

        # Pull SSLKEYLOGFILE if present
        keylog = "/data/local/tmp/apktrace/sslkeylog.txt"
        rc, _, _ = fleet_adb.adb(
            ["shell", "test", "-f", keylog], serial=serial, timeout=5,
        )
        if rc == 0:
            fleet_adb.pull_file(serial, keylog,
                               os.path.join(rom_dir, "sslkeylog.txt"))

        # Stop tracing
        fleet_adb.adb(
            ["shell", "apktrace", "stop", package],
            serial=serial, timeout=10,
        )

        # Remove UID from kernel module
        rc, out, _ = fleet_adb.adb(
            ["shell", "pm", "list", "packages", "-U", package],
            serial=serial, timeout=10,
        )
        if rc == 0 and "uid:" in out:
            import re
            m = re.search(r'uid:(\d+)', out)
            if m:
                fleet_adb.adb(
                    ["shell", "su", "-c",
                     f"echo -{m.group(1)} > /proc/apktrace_ctl"],
                    serial=serial, timeout=5,
                )

        size = sum(
            os.path.getsize(os.path.join(rom_dir, f))
            for f in os.listdir(rom_dir)
            if os.path.isfile(os.path.join(rom_dir, f))
        ) if os.path.exists(rom_dir) else 0
        log.info("[%s] ROM trace stopped for %s, pulled %.1f KB",
                 serial, package, size / 1024)
        return True

    def requires_running_process(self) -> bool:
        return False  # Hooks activate when app starts


# Ordered list of backend classes — instantiated per-worker.
# ROM backend preferred (research ROM), falls back to Frida/eBPF/strace.
DEFAULT_BACKEND_CLASSES = [RomTraceBackend, FridaBackend, EbpfBackend, StraceBackend]


# ---------------------------------------------------------------------------
# Serial debug capture
# ---------------------------------------------------------------------------

class SerialCapture:
    """Captures kernel console output from a Pixel serial debug cable."""

    MAX_BUFFER_LINES = 50_000

    def __init__(self, serial_port: str, baud_rate: int = TRACE_SERIAL_BAUD):
        self.serial_port = serial_port
        self.baud_rate = baud_rate
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._buffer: List[str] = []
        self._truncated = False

    def start(self) -> bool:
        if not self.serial_port or not os.path.exists(self.serial_port):
            return False
        try:
            import serial as pyserial
            self._ser = pyserial.Serial(
                self.serial_port, self.baud_rate, timeout=1
            )
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._read_loop, daemon=True
            )
            self._thread.start()
            return True
        except Exception:
            log.exception("Failed to open serial port %s", self.serial_port)
            return False

    def stop(self) -> List[str]:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        if hasattr(self, "_ser"):
            self._ser.close()
        return self._buffer

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.writelines(self._buffer)

    def _read_loop(self) -> None:
        while not self._stop.is_set():
            try:
                line = self._ser.readline().decode("utf-8", errors="replace")
                if line:
                    if len(self._buffer) < self.MAX_BUFFER_LINES:
                        self._buffer.append(line)
                    elif not self._truncated:
                        self._buffer.append(
                            "[serial capture truncated after memory cap]\n"
                        )
                        self._truncated = True
            except Exception:
                break


# ---------------------------------------------------------------------------
# Trace worker
# ---------------------------------------------------------------------------

class TraceWorker:
    """
    One per rooted Pixel 8a.  Claims trace jobs and captures runtime traces.
    """

    def __init__(self, serial: str, db_path: str = FLEET_DB_PATH,
                 backends: List[TracingBackend] = None):
        self.serial = serial
        self.db_path = db_path
        self.backends = backends or [cls() for cls in DEFAULT_BACKEND_CLASSES]
        self.running = True
        self._stop_event = threading.Event()
        self._short = serial[-8:] if len(serial) > 8 else serial
        self._serial_port: Optional[str] = None

    def run(self) -> None:
        log.info("[%s] Trace worker started", self._short)

        # Look up serial port mapping from device_registry
        conn = fleet_db.connect(self.db_path)
        try:
            device = fleet_db.get_device(conn, self.serial)
            if device:
                self._serial_port = device["serial_port"]
        finally:
            conn.close()

        while self.running and not self._stop_event.is_set():
            if not fleet_adb.is_online(self.serial):
                log.warning("[%s] Trace device offline — sleeping 60s", self._short)
                if not self._wait_or_stop(60):
                    break
                continue

            # Claim a trace job
            conn = fleet_db.connect(self.db_path)
            try:
                job = fleet_db.claim_trace_job(conn, self.serial)
            finally:
                conn.close()

            if job is None:
                if not self._wait_or_stop(30):
                    break
                continue

            log.info("[%s] Processing trace job #%d: %s vc%d",
                     self._short, job["id"], job["package"], job["version_code"])

            try:
                self._execute_trace(job)
            except Exception:
                log.exception("[%s] Trace job #%d failed", self._short, job["id"])
                conn = fleet_db.connect(self.db_path)
                try:
                    fleet_db.fail_trace_job(conn, job["id"],
                                            "unhandled exception")
                finally:
                    conn.close()

    def stop(self) -> None:
        self.running = False
        self._stop_event.set()

    def _execute_trace(self, job) -> None:
        package = fleet_db.validate_android_package(job["package"])
        version_code = job["version_code"]
        nas_apk_path = job["nas_apk_path"]
        job_id = job["id"]

        stage_root = os.path.join(TRACE_STAGING_DIR, self.serial)
        os.makedirs(stage_root, exist_ok=True)
        stage_dir = tempfile.mkdtemp(
            prefix=f"{package}_vc{version_code}_job{job_id}_",
            dir=stage_root,
        )
        serial_capture: Optional[SerialCapture] = None
        backend: Optional[TracingBackend] = None
        backend_started = False

        try:
            # --- 1. Sideload APK from NAS ---
            if not self._sideload(package, nas_apk_path):
                self._fail_job(job_id, "sideload failed")
                return

            # --- 2. Start serial capture ---
            if self._serial_port:
                serial_capture = SerialCapture(self._serial_port)
                if serial_capture.start():
                    log.debug("[%s] Serial capture started on %s",
                              self._short, self._serial_port)
                else:
                    serial_capture = None

            # --- 3. Start tracing backend ---
            backend, app_launched = self._start_backend_with_fallback(package, stage_dir)
            if backend is None:
                self._fail_job(job_id, "all tracing backends failed to start")
                return
            backend_started = True

            # --- 4. Launch app ---
            if not app_launched:
                self._launch_app(package)

            # --- 5. Wait trace duration ---
            log.info("[%s] Tracing %s for %ds...", self._short, package,
                     TRACE_DURATION_SEC)
            trace_start = time.time()
            if not self._wait_or_stop(TRACE_DURATION_SEC):
                self._fail_job(job_id, "worker stopped during trace")
                return
            duration = time.time() - trace_start

            # --- 6. Stop traces ---
            if not backend.stop(self.serial, package, stage_dir):
                backend_started = False
                self._fail_job(job_id, f"{backend.name} backend failed to stop cleanly")
                return
            backend_started = False

            # --- 7. Stop serial capture ---
            if serial_capture:
                serial_capture.stop()
                serial_dir = os.path.join(stage_dir, "serial")
                serial_capture.save(os.path.join(serial_dir, "console.log"))
                serial_capture = None

            if not self._trace_artifacts_present(stage_dir, backend.name):
                self._fail_job(job_id, f"{backend.name} produced no trace data")
                return

            # --- 8. Commit to NAS ---
            nas_path = self._commit_to_nas(package, version_code, stage_dir, job_id)
            trace_sha256 = _artifact_tree_sha256(nas_path)

            # --- 9. Build meta.json ---
            meta = {
                "package": package,
                "version_code": version_code,
                "device_serial": self.serial,
                "tracing_backend": backend.name,
                "duration_sec": duration,
                "trace_duration_sec": TRACE_DURATION_SEC,
                "trace_sha256": trace_sha256,
                "serial_port": self._serial_port,
                "serial_baud": TRACE_SERIAL_BAUD if self._serial_port else None,
                "completed_at": time.time(),
            }
            meta_path = os.path.join(nas_path, "meta.json")
            with open(meta_path, "w") as f:
                json.dump(meta, f, indent=2)

            # --- 10. COMPLETE sentinel ---
            open(os.path.join(nas_path, "COMPLETE"), "w").close()

            # --- 11. Profile wipe lite ---
            self._wipe_profile(package)

            # --- 12. Record results ---
            conn = fleet_db.connect(self.db_path)
            try:
                fleet_db.complete_trace_job_with_result(
                    conn, job_id, package, version_code, self.serial,
                    nas_path=nas_path,
                    duration_sec=duration,
                    tracing_backend=backend.name,
                    meta_json=json.dumps(meta),
                    sha256=trace_sha256,
                )
            finally:
                conn.close()

            log.info("[%s] Trace complete: %s vc%d → %s (%s, %.0fs)",
                     self._short, package, version_code, nas_path,
                     backend.name, duration)

        finally:
            if backend_started and backend is not None:
                try:
                    backend.stop(self.serial, package, stage_dir)
                except Exception:
                    log.exception("[%s] Failed to clean up %s backend for %s",
                                  self._short, backend.name, package)
            if serial_capture:
                try:
                    serial_capture.stop()
                    serial_dir = os.path.join(stage_dir, "serial")
                    serial_capture.save(os.path.join(serial_dir, "console.log"))
                except Exception:
                    log.exception("[%s] Failed to finalize serial capture for %s",
                                  self._short, package)
            _cleanup(stage_dir)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _sideload(self, package: str, nas_apk_path: str) -> bool:
        """Sideload APK from NAS onto device."""
        if not nas_apk_path or not os.path.exists(nas_apk_path):
            log.warning("[%s] NAS APK path missing: %s", self._short, nas_apk_path)
            return False

        # Uninstall if present
        if fleet_adb.is_installed(self.serial, package):
            fleet_adb.uninstall(self.serial, package)

        apks = sorted(_glob.glob(os.path.join(nas_apk_path, "*.apk")))
        if not apks:
            log.warning("[%s] No APKs in %s", self._short, nas_apk_path)
            return False

        if len(apks) > 1:
            rc, err = fleet_adb.install_multiple(self.serial, apks)
        else:
            rc, err = fleet_adb.install_apk(self.serial, apks[0])

        if rc != 0:
            log.warning("[%s] Sideload failed: %s", self._short, err)
            return False

        return True

    def _select_backend(self) -> Optional[TracingBackend]:
        """Select the first available tracing backend."""
        for backend in self.backends:
            if backend.is_available(self.serial):
                return backend
        return None

    def _start_backend_with_fallback(self, package: str,
                                     stage_dir: str) -> tuple[Optional[TracingBackend], bool]:
        app_launched = False
        for backend in self.backends:
            if not backend.is_available(self.serial):
                continue
            if backend.requires_running_process() and not app_launched:
                self._launch_app(package)
                app_launched = True
                if not self._wait_or_stop(2):
                    return None, app_launched
            if backend.start(self.serial, package, stage_dir):
                log.info("[%s] Using %s backend for %s",
                         self._short, backend.name, package)
                # For eBPF: update PID filter after app launches
                if isinstance(backend, EbpfBackend) and not app_launched:
                    self._launch_app(package)
                    app_launched = True
                    if not self._wait_or_stop(2):
                        return None, app_launched
                    backend._update_pid_filter(self.serial, package)
                return backend, app_launched
            log.warning("[%s] %s backend failed to start",
                        self._short, backend.name)
        return None, app_launched

    def _launch_app(self, package: str) -> None:
        """Launch the app via am start."""
        # Get the main activity
        rc, out, _ = fleet_adb.adb(
            ["shell", "cmd", "package", "resolve-activity",
             "--brief", package],
            serial=self.serial, timeout=10
        )
        if rc == 0 and out:
            lines = out.strip().splitlines()
            # Last line should be component name
            component = lines[-1].strip() if lines else None
            if component and "/" in component:
                fleet_adb.adb(
                    ["shell", "am", "start", "-n", component],
                    serial=self.serial, timeout=10
                )
                return

        # Fallback: monkey launcher
        fleet_adb.adb(
            ["shell", "monkey", "-p", package,
             "-c", "android.intent.category.LAUNCHER", "1"],
            serial=self.serial, timeout=10
        )

    def _commit_to_nas(self, package: str, version_code: int,
                       stage_dir: str, job_id: int) -> str:
        """Copy trace data from staging to NAS. Returns NAS path."""
        nas_path = os.path.join(
            TRACE_NAS_DIR, package, f"vc{version_code}"
        )
        partial = f"{nas_path}.partial.{job_id}.{uuid.uuid4().hex}"
        backup = f"{nas_path}.old.{job_id}.{uuid.uuid4().hex}"

        # Copy staging subdirs to NAS
        os.makedirs(os.path.dirname(nas_path), exist_ok=True)
        os.makedirs(partial, exist_ok=False)
        copied_any = False
        for subdir in TRACE_ARTIFACT_SUBDIRS:
            src = os.path.join(stage_dir, subdir)
            if os.path.exists(src) and os.listdir(src):
                dst = os.path.join(partial, subdir)
                shutil.copytree(src, dst)
                copied_any = True
        if not copied_any:
            shutil.rmtree(partial, ignore_errors=True)
            raise RuntimeError("no trace artifacts were staged for commit")

        restored = False
        if os.path.exists(nas_path):
            os.rename(nas_path, backup)
        try:
            os.rename(partial, nas_path)
        except Exception:
            if os.path.exists(backup) and not os.path.exists(nas_path):
                os.rename(backup, nas_path)
                restored = True
            shutil.rmtree(partial, ignore_errors=True)
            raise
        if os.path.exists(backup) and not restored:
            shutil.rmtree(backup, ignore_errors=True)
        return nas_path

    def _wipe_profile(self, package: str) -> None:
        """Profile wipe lite: uninstall, clear user packages, reset perms."""
        fleet_adb.uninstall(self.serial, package)
        # Clear leftover data
        fleet_adb.adb(
            ["shell", "pm", "clear", package],
            serial=self.serial, timeout=10
        )
        # Remove trace temp files
        fleet_adb.adb(
            ["shell", "rm", "-rf", "/data/local/tmp/frida*",
             "/data/local/tmp/strace*"],
            serial=self.serial, timeout=10
        )

    def _fail_job(self, job_id: int, error: str) -> None:
        conn = fleet_db.connect(self.db_path)
        try:
            fleet_db.fail_trace_job(conn, job_id, error)
        finally:
            conn.close()

    def _wait_or_stop(self, seconds: float) -> bool:
        return not self._stop_event.wait(seconds)

    def _trace_artifacts_present(self, stage_dir: str, backend_name: str) -> bool:
        expected = {
            "rom": [os.path.join(stage_dir, "rom", f) for f in
                    ("tls_plaintext.jsonl", "kernel.jsonl", "framework.jsonl")],
            "frida": [os.path.join(stage_dir, "frida", "trace.jsonl")],
            "ebpf": [os.path.join(stage_dir, "ebpf", "trace.dat")],
            "strace": [os.path.join(stage_dir, "strace", "strace.log")],
        }
        return any(_is_nonempty_file(path) for path in expected.get(backend_name, []))


def _cleanup(stage_dir: str) -> None:
    try:
        shutil.rmtree(stage_dir, ignore_errors=True)
    except Exception:
        pass


def _is_nonempty_file(path: str) -> bool:
    return os.path.isfile(path) and os.path.getsize(path) > 0


def _artifact_tree_sha256(base_dir: str) -> str:
    hasher = hashlib.sha256()
    file_count = 0
    for subdir in TRACE_ARTIFACT_SUBDIRS:
        root = os.path.join(base_dir, subdir)
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for filename in sorted(filenames):
                path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(path, base_dir).replace(os.sep, "/")
                hasher.update(rel_path.encode("utf-8"))
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        hasher.update(chunk)
                file_count += 1
    if file_count == 0:
        raise ValueError(f"no trace artifacts found under {base_dir}")
    return hasher.hexdigest()
