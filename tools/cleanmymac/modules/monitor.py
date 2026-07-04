"""
Real-time system monitor for macOS.
Shows CPU, memory, disk, network, battery, and per-process stats.
"""

import os
import subprocess
import time
from pathlib import Path
from modules.utils import human_size, run_cmd


class SystemMonitor:
    """Real-time macOS system monitoring."""

    def __init__(self):
        self.home = Path.home()
        self._prev_net = None
        self._prev_time = None

    def _run(self, cmd, shell=False):
        return run_cmd(cmd, shell=shell)

    def _human_size(self, size_bytes):
        return human_size(size_bytes)

    def _get_cpu(self):
        """Get CPU usage via top."""
        out = self._run("top -l 1 -n 0 | grep 'CPU usage'", shell=True)
        if out:
            return out.replace("CPU usage: ", "")
        return "unknown"

    def _get_memory(self):
        """Get memory stats via vm_stat."""
        out = self._run(["vm_stat"])
        if not out:
            return {}

        stats = {}
        page_size = 16384  # Apple Silicon default
        for line in out.splitlines():
            if "page size of" in line:
                try:
                    page_size = int(line.split()[-2])
                except (ValueError, IndexError):
                    pass
            elif ":" in line:
                key, val = line.split(":", 1)
                try:
                    stats[key.strip()] = int(val.strip().rstrip(".")) * page_size
                except ValueError:
                    pass

        total_out = self._run(["sysctl", "-n", "hw.memsize"])
        total = int(total_out) if total_out.isdigit() else 0

        active = stats.get("Pages active", 0)
        wired = stats.get("Pages wired down", 0)
        compressed = stats.get("Pages occupied by compressor", 0)
        free = stats.get("Pages free", 0)
        used = active + wired + compressed

        return {
            "total": total,
            "used": used,
            "free": free,
            "active": active,
            "wired": wired,
            "compressed": compressed,
            "percent": (used / total * 100) if total else 0,
        }

    def _get_disk(self):
        """Get disk usage."""
        out = self._run(["df", "-H", "/"])
        if out:
            lines = out.splitlines()
            if len(lines) >= 2:
                parts = lines[1].split()
                if len(parts) >= 5:
                    return {
                        "total": parts[1],
                        "used": parts[2],
                        "available": parts[3],
                        "percent": parts[4],
                    }
        return {}

    def _get_battery(self):
        """Get battery info."""
        out = self._run("pmset -g batt", shell=True)
        if "Battery" in out or "InternalBattery" in out:
            for line in out.splitlines():
                if "InternalBattery" in line or "%" in line:
                    return line.strip()
        return "No battery / Desktop"

    def _get_thermal(self):
        """Get thermal pressure (Apple Silicon compatible)."""
        # Try Apple Silicon thermal pressure first
        out = self._run(["sysctl", "-n", "kern.memorystatus_vm_pressure_level"])
        if out and out.isdigit():
            level = int(out)
            labels = {1: "Normal", 2: "Warning", 4: "Critical"}
            return labels.get(level, f"Level {level}")
        # Fallback to Intel thermal level
        out = self._run(["sysctl", "-n", "machdep.xcpm.cpu_thermal_level"])
        if out and out.isdigit():
            level = int(out)
            labels = {0: "Normal", 1: "Moderate", 2: "Heavy", 3: "Trapping", 4: "Sleeping"}
            return labels.get(level, f"Level {level}")
        # Last resort: check thermal state via powermetrics hint
        out = self._run("sysctl -n hw.cpufrequency_max 2>/dev/null", shell=True)
        if out:
            return "Normal"
        return "N/A"

    def _get_top_processes(self, count=10):
        """Get top processes by CPU."""
        out = self._run(f"ps aux | sort -nrk 3 | head -{count}", shell=True)
        procs = []
        for line in out.splitlines():
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({
                    "user": parts[0],
                    "pid": parts[1],
                    "cpu": parts[2],
                    "mem": parts[3],
                    "command": parts[10][:50],
                })
        return procs

    def _get_network_connections(self):
        """Get active network connection count."""
        out = self._run("netstat -an | grep ESTABLISHED | wc -l", shell=True)
        return out.strip() if out else "0"

    def _get_network_throughput(self):
        """Get network bytes in/out using netstat, with per-second rate if available."""
        out = self._run("netstat -ib 2>/dev/null", shell=True)
        if not out:
            return None
        total_in = 0
        total_out = 0
        seen = set()
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 7:
                iface = parts[0]
                # Skip loopback and duplicates
                if iface.startswith("lo") or iface in seen:
                    continue
                seen.add(iface)
                try:
                    ibytes = int(parts[6])
                    obytes = int(parts[9]) if len(parts) > 9 else 0
                    total_in += ibytes
                    total_out += obytes
                except (ValueError, IndexError):
                    pass

        current = {"in": total_in, "out": total_out}
        now = time.time()

        # Calculate per-second rate if we have a previous sample
        rate = None
        if self._prev_net and self._prev_time:
            elapsed = now - self._prev_time
            if elapsed > 0:
                rate = {
                    "in": (total_in - self._prev_net["in"]) / elapsed,
                    "out": (total_out - self._prev_net["out"]) / elapsed,
                }

        self._prev_net = current
        self._prev_time = now

        if total_in or total_out:
            return {"total_in": total_in, "total_out": total_out, "rate": rate}
        return None

    def _get_uptime(self):
        """Get system uptime."""
        out = self._run(["uptime"])
        return out.strip() if out else "unknown"

    def _bar(self, percent, width=30):
        """Render a progress bar."""
        filled = int(width * percent / 100)
        return f"[{'█' * filled}{'░' * (width - filled)}] {percent:.0f}%"

    def snapshot(self):
        """Take a single system snapshot."""
        cpu = self._get_cpu()
        mem = self._get_memory()
        disk = self._get_disk()
        battery = self._get_battery()
        thermal = self._get_thermal()
        connections = self._get_network_connections()
        net = self._get_network_throughput()
        uptime = self._get_uptime()
        procs = self._get_top_processes(8)

        print("━" * 55)
        print("  🖥️  SYSTEM MONITOR")
        print("━" * 55)
        print(f"\n  Uptime: {uptime}")
        print(f"  Thermal: {thermal}")
        print(f"  Battery: {battery}")
        print(f"  Network connections: {connections}")
        if net:
            print(f"  Network total: ↓ {self._human_size(net['total_in'])} received, ↑ {self._human_size(net['total_out'])} sent")
            if net["rate"]:
                print(f"  Network rate:  ↓ {self._human_size(net['rate']['in'])}/s, ↑ {self._human_size(net['rate']['out'])}/s")

        print(f"\n  ⚡ CPU: {cpu}")

        if mem:
            print(f"\n  🧠 Memory: {self._bar(mem['percent'])}")
            print(f"     Total: {self._human_size(mem['total'])}")
            print(f"     Used:  {self._human_size(mem['used'])} "
                  f"(Active: {self._human_size(mem['active'])}, "
                  f"Wired: {self._human_size(mem['wired'])}, "
                  f"Compressed: {self._human_size(mem['compressed'])})")
            print(f"     Free:  {self._human_size(mem['free'])}")

        if disk:
            print(f"\n  💾 Disk: {disk['used']} / {disk['total']} ({disk['percent']} used)")
            print(f"     Available: {disk['available']}")

        if procs:
            print(f"\n  🔥 Top Processes (by CPU):")
            print(f"     {'PID':<8}{'CPU%':<7}{'MEM%':<7}{'COMMAND'}")
            for p in procs:
                print(f"     {p['pid']:<8}{p['cpu']:<7}{p['mem']:<7}{p['command']}")

        print("\n" + "━" * 55)

    def live(self, interval=2):
        """Live updating monitor."""
        print("  Press Ctrl+C to stop\n")
        try:
            while True:
                os.system("clear")
                self.snapshot()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n  Monitor stopped.")
