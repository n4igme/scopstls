#!/usr/bin/env python3
"""
CleanMyMac — macOS system utility (Python CLI)
Features: junk cleanup, security scan, app uninstall, system monitor
"""

import argparse
import sys
import os

# Ensure our modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.cleanup import JunkScanner
from modules.security import SecurityScanner
from modules.uninstaller import AppUninstaller
from modules.monitor import SystemMonitor
from modules.malware import MalwareAnalyzer
from modules.utils import VERSION


def banner():
    print("""
╔═══════════════════════════════════════════╗
║         🧹 CleanMyMac (Python)           ║
║   System Junk · Security · Uninstall     ║
╚═══════════════════════════════════════════╝
    """)


HELP_TEXT = """USAGE:
  cleanmymac <command> [options]

COMMANDS:
  scan          Scan for junk files (dry run, nothing deleted)
  clean         Remove junk files (with confirmation)
  security      Run full macOS security audit
  uninstall     Remove apps and all their remnants
  monitor       Real-time system resource monitoring

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SCAN — Preview what can be cleaned:
  cleanmymac scan                  Quick scan (caches, logs, packages)
  cleanmymac scan --all            Full system disk breakdown + large files

CLEAN — Remove junk files:
  cleanmymac clean                 Clean all safe items (with confirmation)
  cleanmymac clean -y              Skip confirmation prompt
  cleanmymac clean --select        Interactive: pick individual items by number
  cleanmymac clean --category X    Only clean a specific category:
                                     caches, logs, brew, packages, xcode, trash
  cleanmymac clean --exclude X     Skip items by name (comma-separated):
                                     e.g. --exclude spotify,playwright

  Selection syntax (with --select):
    1,3,7       individual items
    1-5,8-10    ranges
    1,3,5-8     mixed
    a           select all
    q / Enter   cancel

SECURITY — macOS security audit:
  cleanmymac security              Full audit: firewall, SIP, FileVault,
                                   Gatekeeper, ports, sharing, DNS, malware,
                                   screen lock, updates, and more

MALWARE — Deep malware analysis:
  cleanmymac malware               Process anomalies, persistence audit,
                                   network C2, codesigning, dylib hijacking,
                                   browser extensions, cryptominers, TCC abuse

UNINSTALL — Remove apps cleanly:
  cleanmymac uninstall --list              List all apps with sizes
  cleanmymac uninstall --list --top 10     Show only top 10 largest apps
  cleanmymac uninstall --app Postman       Remove app + all remnants
  cleanmymac uninstall --app Postman --dry-run   Preview what would be removed

MONITOR — System resources:
  cleanmymac monitor               Live updating (Ctrl+C to stop)
  cleanmymac monitor --once        Single snapshot
  cleanmymac monitor --interval 5  Custom refresh rate (seconds)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FILES:
  Audit log:   ~/.cleanmymac_audit.log    (tracks all deletions)
  Source:      ~/Project/cleanmymac/

SAFETY:
  • 'clean' never deletes Downloads or Docker without explicit selection
  • All destructive operations require confirmation (bypass with -y)
  • Uninstall checks if app is running before removing
  • Every deletion is logged with timestamp and path
"""


def _interactive_select(results, scanner):
    """Show numbered items and let user pick which to delete."""
    import shutil
    import os

    all_items = []
    print("\n  Select items to delete (enter numbers separated by commas, 'a' for all, 'q' to cancel):\n")

    idx = 1
    for category, items in results.items():
        print(f"  ── {category} ──")
        for item in items:
            age_str = f"{int(item['age_days'])}d" if item['age_days'] > 0 else "new"
            print(f"  [{idx:>3}] {scanner._human_size(item['size']):>10}  {age_str:<6} {item['name'][:45]}")
            all_items.append(item)
            idx += 1
        print()

    choice = input("  Selection: ").strip().lower()
    if choice in ("q", "quit", ""):
        return []
    if choice == "a":
        return all_items

    # Parse selection (e.g. "1,3,5-8,12")
    selected = []
    for part in choice.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                for i in range(int(start), int(end) + 1):
                    if 1 <= i <= len(all_items):
                        selected.append(all_items[i - 1])
            except ValueError:
                pass
        else:
            try:
                i = int(part)
                if 1 <= i <= len(all_items):
                    selected.append(all_items[i - 1])
            except ValueError:
                pass

    return selected


def _delete_selected(items, scanner):
    """Delete a list of specific items and log them."""
    import shutil
    import os
    from modules.cleanup import AUDIT_LOG
    from datetime import datetime

    errors = []
    cleaned = []
    for item in items:
        path = item["path"]
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            cleaned.append(item)
            print(f"  ✅ {item['name']}")
        except (PermissionError, OSError) as e:
            errors.append(item)
            print(f"  ❌ {item['name']} — {e}")

    total = sum(i["size"] for i in cleaned)
    print(f"\n  Deleted {len(cleaned)} items ({scanner._human_size(total)})")
    if errors:
        print(f"  ⚠️  {len(errors)} items failed (may need sudo)")

    # Audit log
    if cleaned:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(AUDIT_LOG, "a") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"  CleanMyMac (selective) — {timestamp}\n")
            f.write(f"  Deleted {len(cleaned)} items ({scanner._human_size(total)})\n")
            f.write(f"{'='*60}\n")
            for item in cleaned:
                f.write(f"  {scanner._human_size(item['size']):>10}  {item['path']}\n")
            f.write("\n")


def cmd_scan(args):
    """Scan for junk files without deleting."""
    scanner = JunkScanner()
    results = scanner.scan(dry_run=True)
    scanner.print_report(results)
    if args.all:
        _print_disk_breakdown()


def _print_disk_breakdown():
    """Show system disk usage breakdown."""
    from modules.utils import run_cmd as _run, human_size as _hs
    print("\n  💾 System Disk Breakdown:\n")
    # Top-level directories
    out = _run("du -d1 -h / 2>/dev/null | sort -rh | head -15", shell=True)
    if out:
        for line in out.splitlines()[1:]:  # skip total
            parts = line.strip().split("\t", 1)
            if len(parts) == 2:
                print(f"    {parts[0]:>8}  {parts[1]}")
    print()
    # Large files in home
    print("  📁 Largest files in ~/:\n")
    out = _run("find ~ -type f -size +100M 2>/dev/null | head -10 | while read f; do du -h \"$f\" 2>/dev/null; done | sort -rh", shell=True)
    if out:
        for line in out.splitlines()[:10]:
            print(f"    {line}")
    else:
        print("    No files > 100MB found")


def cmd_clean(args):
    """Scan and clean junk files."""
    scanner = JunkScanner()
    results = scanner.scan(dry_run=True)

    # Category mapping for --category flag
    category_map = {
        "caches": "User Caches",
        "logs": "System Logs",
        "brew": "Homebrew Cache",
        "packages": "Package Caches (pip/npm/yarn/HF)",
        "xcode": "Xcode Data",
        "trash": "Trash",
    }

    # Filter to specific category if requested
    if args.category:
        cat_key = args.category.lower()
        if cat_key not in category_map:
            print(f"  ❌ Unknown category '{args.category}'")
            print(f"  Available: {', '.join(category_map.keys())}")
            return
        target_cat = category_map[cat_key]
        results = {k: v for k, v in results.items() if k == target_cat}
        if not results:
            print(f"  Nothing found for category '{args.category}'.")
            return

    # Interactive selection mode
    if args.select:
        # Filter out excluded items before selection
        exclude = None
        if args.exclude:
            exclude = [e.strip() for e in args.exclude.split(",")]
            filtered = {}
            for cat, items in results.items():
                filtered_items = [i for i in items if not any(ex.lower() in i["name"].lower() for ex in exclude)]
                if filtered_items:
                    filtered[cat] = filtered_items
            results = filtered
        selected = _interactive_select(results, scanner)
        if not selected:
            print("  Nothing selected. Cancelled.")
            return
        # Delete selected items
        total_size = sum(i["size"] for i in selected)
        print(f"\n  ⚠️  About to delete {len(selected)} items ({scanner._human_size(total_size)}).")
        if not args.yes:
            confirm = input("  Proceed? [y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                print("  Cancelled.")
                return
        _delete_selected(selected, scanner)
        return

    scanner.print_report(results)

    # Calculate safe-to-delete size
    safe_categories = {"User Caches", "System Logs", "Homebrew Cache", "Trash",
                       "Package Caches (pip/npm/yarn/HF)", "Xcode Data"}
    safe_size = sum(
        sum(i["size"] for i in items)
        for cat, items in results.items() if cat in safe_categories
    )

    if safe_size == 0:
        print("\n  Nothing to clean.")
        return

    # Format size for prompt
    size_str = scanner._human_size(safe_size)

    # Determine category filter
    only_cats = None
    if args.category:
        only_cats = {category_map[args.category.lower()]}

    # Parse exclude list
    exclude = None
    if args.exclude:
        exclude = [e.strip() for e in args.exclude.split(",")]

    if not args.yes:
        print(f"\n  ⚠️  About to delete {size_str} of safe-to-remove items.")
        if exclude:
            print(f"  Excluding: {', '.join(exclude)}")
        confirm = input("  Proceed? [y/N]: ").strip().lower()
        if confirm not in ("y", "yes"):
            print("  Cancelled.")
            return

    # Delete from the already-scanned results (no second scan)
    scanner.clean_results(results, only_categories=only_cats, exclude=exclude)
    scanner.print_report(results, cleaned=True)


def cmd_security(args):
    """Run security audit."""
    sec = SecurityScanner()
    sec.run_full_scan()


def cmd_uninstall(args):
    """Uninstall an app and its remnants."""
    uninstaller = AppUninstaller()
    if args.list:
        top_n = args.top if args.top > 0 else None
        uninstaller.list_apps(top_n=top_n)
    elif args.app:
        uninstaller.uninstall(args.app, dry_run=args.dry_run)
    else:
        print("Specify --app <name> or --list")


def cmd_monitor(args):
    """Real-time system monitoring."""
    mon = SystemMonitor()
    if args.once:
        mon.snapshot()
    else:
        mon.live(interval=args.interval)


def cmd_malware(args):
    """Run malware analysis."""
    analyzer = MalwareAnalyzer()
    analyzer.run_full_analysis()


def cmd_log(args):
    """View audit log of past deletions."""
    from modules.cleanup import AUDIT_LOG
    if not AUDIT_LOG.exists():
        print("  No audit log yet. Run 'cleanmymac clean' to start logging.")
        return
    # Show last 50 lines by default
    with open(AUDIT_LOG, "r") as f:
        lines = f.readlines()
    if not lines:
        print("  Audit log is empty.")
        return
    # Show last 60 lines (roughly last 2-3 sessions)
    tail = lines[-60:] if len(lines) > 60 else lines
    print(f"  📋 Audit Log ({AUDIT_LOG})\n")
    for line in tail:
        print(f"  {line.rstrip()}")
    print(f"\n  ({len(lines)} total lines in log)")


def main():
    # Check for --version early (no banner)
    if "--version" in sys.argv or "-v" in sys.argv:
        print(f"  cleanmymac v{VERSION}")
        return

    # Check for --quiet early
    if "--quiet" not in sys.argv and "-q" not in sys.argv:
        banner()

    parser = argparse.ArgumentParser(
        prog="cleanmymac",
        description="macOS system utility — cleanup, security, uninstall, monitor",
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="store_true", help="Show help")
    parser.add_argument("--version", "-v", action="store_true", help="Show version")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress banner output")
    sub = parser.add_subparsers(dest="command")

    # Scan
    p_scan = sub.add_parser("scan", help="Scan for junk (dry run)")
    p_scan.add_argument("--all", "-a", action="store_true", help="Show full system disk breakdown")

    # Clean
    p_clean = sub.add_parser("clean", help="Scan and remove junk files")
    p_clean.add_argument("--category", type=str, help="Only clean specific category (caches, logs, brew, packages, xcode, trash)")
    p_clean.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")
    p_clean.add_argument("--select", "-s", action="store_true", help="Interactive item selection mode")
    p_clean.add_argument("--exclude", type=str, help="Comma-separated names to skip (e.g. spotify,playwright)")

    # Security
    sub.add_parser("security", help="Security audit")

    # Uninstall
    p_uninstall = sub.add_parser("uninstall", help="Uninstall apps cleanly")
    p_uninstall.add_argument("--app", type=str, help="App name to uninstall")
    p_uninstall.add_argument("--list", action="store_true", help="List installed apps")
    p_uninstall.add_argument("--dry-run", action="store_true", help="Show what would be removed")
    p_uninstall.add_argument("--top", type=int, default=0, help="Show top N apps by size (0=all)")

    # Monitor
    p_monitor = sub.add_parser("monitor", help="System resource monitor")
    p_monitor.add_argument("--once", action="store_true", help="Single snapshot")
    p_monitor.add_argument("--interval", type=int, default=2, help="Refresh interval (seconds)")

    # Malware
    sub.add_parser("malware", help="Deep malware analysis")

    # Log
    sub.add_parser("log", help="View audit log of past deletions")

    args = parser.parse_args()

    if args.version:
        print(f"  cleanmymac v{VERSION}")
        return

    if args.help or not args.command:
        print(HELP_TEXT)
        return

    commands = {
        "scan": cmd_scan,
        "clean": cmd_clean,
        "security": cmd_security,
        "uninstall": cmd_uninstall,
        "monitor": cmd_monitor,
        "malware": cmd_malware,
        "log": cmd_log,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
