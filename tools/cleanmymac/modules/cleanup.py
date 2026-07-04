"""
Junk file scanner and cleaner for macOS.
Scans caches, logs, downloads, broken symlinks, app leftovers.
"""

import os
import shutil
import subprocess
import time
import json
from pathlib import Path
from datetime import datetime
from modules.utils import human_size, dir_size, run_cmd


AUDIT_LOG = Path.home() / ".cleanmymac_audit.log"


class JunkScanner:
    """Scan and clean system/user junk files."""

    def __init__(self):
        self.home = Path.home()
        self.categories = {}

    def _human_size(self, size_bytes):
        return human_size(size_bytes)

    def _dir_size(self, path):
        return dir_size(path)

    def _file_age_days(self, path):
        """Get file age in days."""
        try:
            mtime = os.path.getmtime(path)
            return (time.time() - mtime) / 86400
        except OSError:
            return 0

    def _scan_user_caches(self):
        """Scan ~/Library/Caches (excluding items covered by other categories)."""
        cache_dir = self.home / "Library" / "Caches"
        # These are reported separately in their own categories
        exclude_names = {"Homebrew", "pip", "Yarn"}
        items = []
        if cache_dir.exists():
            for entry in cache_dir.iterdir():
                if entry.name in exclude_names:
                    continue
                try:
                    size = self._dir_size(entry) if entry.is_dir() else entry.stat().st_size
                    if size > 1_000_000:  # Only report > 1MB
                        items.append({
                            "path": str(entry),
                            "size": size,
                            "name": entry.name,
                            "age_days": self._file_age_days(entry),
                        })
                except (PermissionError, OSError):
                    pass
        return sorted(items, key=lambda x: x["size"], reverse=True)

    def _scan_system_logs(self):
        """Scan ~/Library/Logs and /var/log (user-accessible)."""
        items = []
        log_dirs = [
            self.home / "Library" / "Logs",
            Path("/var/log"),
        ]
        for log_dir in log_dirs:
            if not log_dir.exists():
                continue
            for root, dirs, files in os.walk(log_dir):
                for f in files:
                    fp = Path(root) / f
                    try:
                        size = fp.stat().st_size
                        if size > 500_000:  # > 500KB
                            items.append({
                                "path": str(fp),
                                "size": size,
                                "name": f,
                                "age_days": self._file_age_days(fp),
                            })
                    except (PermissionError, OSError):
                        pass
        return sorted(items, key=lambda x: x["size"], reverse=True)

    def _scan_xcode(self):
        """Scan Xcode derived data and archives."""
        items = []
        xcode_paths = [
            self.home / "Library" / "Developer" / "Xcode" / "DerivedData",
            self.home / "Library" / "Developer" / "Xcode" / "Archives",
            self.home / "Library" / "Developer" / "Xcode" / "iOS DeviceSupport",
            self.home / "Library" / "Developer" / "CoreSimulator" / "Devices",
        ]
        for p in xcode_paths:
            if p.exists():
                size = self._dir_size(p)
                if size > 1_000_000:
                    items.append({
                        "path": str(p),
                        "size": size,
                        "name": p.name,
                        "age_days": self._file_age_days(p),
                    })
        return items

    def _scan_brew(self):
        """Scan Homebrew cache."""
        items = []
        brew_cache = self.home / "Library" / "Caches" / "Homebrew"
        if not brew_cache.exists():
            brew_cache = Path("/opt/homebrew/cache")
        if brew_cache.exists():
            size = self._dir_size(brew_cache)
            if size > 1_000_000:
                items.append({
                    "path": str(brew_cache),
                    "size": size,
                    "name": "Homebrew Cache",
                    "age_days": self._file_age_days(brew_cache),
                })
        return items

    def _scan_trash(self):
        """Scan Trash."""
        items = []
        trash = self.home / ".Trash"
        if trash.exists():
            size = self._dir_size(trash)
            if size > 0:
                items.append({
                    "path": str(trash),
                    "size": size,
                    "name": "Trash",
                    "age_days": 0,
                })
        return items

    def _scan_downloads_old(self, days=30):
        """Scan Downloads for files older than N days."""
        items = []
        downloads = self.home / "Downloads"
        if downloads.exists():
            for entry in downloads.iterdir():
                try:
                    age = self._file_age_days(entry)
                    if age > days:
                        size = self._dir_size(entry) if entry.is_dir() else entry.stat().st_size
                        if size > 1_000_000:
                            items.append({
                                "path": str(entry),
                                "size": size,
                                "name": entry.name,
                                "age_days": age,
                            })
                except (PermissionError, OSError):
                    pass
        return sorted(items, key=lambda x: x["size"], reverse=True)

    def _scan_pip_cache(self):
        """Scan pip/npm/yarn caches."""
        items = []
        cache_dirs = [
            (self.home / "Library" / "Caches" / "pip", "pip cache"),
            (self.home / ".npm" / "_cacache", "npm cache"),
            (self.home / "Library" / "Caches" / "Yarn", "Yarn cache"),
            (self.home / ".cache" / "huggingface", "HuggingFace cache"),
        ]
        for p, name in cache_dirs:
            if p.exists():
                size = self._dir_size(p)
                if size > 5_000_000:
                    items.append({
                        "path": str(p),
                        "size": size,
                        "name": name,
                        "age_days": self._file_age_days(p),
                    })
        return items

    def _scan_docker(self):
        """Check Docker disk usage (actual on-disk, not logical)."""
        items = []
        docker_dir = self.home / "Library" / "Containers" / "com.docker.docker" / "Data"
        if not docker_dir.exists():
            docker_dir = self.home / ".docker"
        if docker_dir.exists():
            # Use du for actual disk usage (handles sparse files correctly)
            import subprocess
            try:
                out = subprocess.run(
                    ["du", "-sk", str(docker_dir)],
                    capture_output=True, text=True, timeout=30
                )
                size = int(out.stdout.split()[0]) * 1024 if out.stdout else 0
            except (subprocess.TimeoutExpired, ValueError, IndexError):
                size = self._dir_size(docker_dir)
            if size > 100_000_000:  # > 100MB
                items.append({
                    "path": str(docker_dir),
                    "size": size,
                    "name": "Docker Data (actual disk usage)",
                    "age_days": self._file_age_days(docker_dir),
                })
        return items

    def scan(self, dry_run=True, only_categories=None):
        """Run all scans. Returns dict of category -> items."""
        print("🔍 Scanning for junk files...\n")

        categories = {
            "User Caches": self._scan_user_caches(),
            "System Logs": self._scan_system_logs(),
            "Xcode Data": self._scan_xcode(),
            "Homebrew Cache": self._scan_brew(),
            "Package Caches (pip/npm/yarn/HF)": self._scan_pip_cache(),
            "Old Downloads (>30 days)": self._scan_downloads_old(),
            "Docker": self._scan_docker(),
            "Trash": self._scan_trash(),
        }

        self.categories = {k: v for k, v in categories.items() if v}

        if not dry_run:
            self._clean(only_categories=only_categories)

        return self.categories

    def clean_results(self, results, only_categories=None, exclude=None):
        """Delete items from already-scanned results (avoids double scan)."""
        self.categories = results
        self._clean(only_categories=only_categories, exclude=exclude)

    def _clean(self, only_categories=None, exclude=None):
        """Delete junk files (except Downloads and Docker — only reports those)."""
        skip_categories = {"Old Downloads (>30 days)", "Docker"}
        cleaned_items = []
        for category, items in self.categories.items():
            if category in skip_categories:
                continue
            # If filtering by category, only clean matching ones
            if only_categories and category not in only_categories:
                continue
            for item in items:
                # Skip excluded patterns
                if exclude and any(ex.lower() in item["name"].lower() for ex in exclude):
                    item["cleaned"] = False
                    item["skipped"] = True
                    continue
                path = item["path"]
                try:
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                    item["cleaned"] = True
                    cleaned_items.append({
                        "path": path,
                        "size": item["size"],
                        "category": category,
                    })
                except (PermissionError, OSError) as e:
                    item["cleaned"] = False
                    item["error"] = str(e)

        # Write audit log
        if cleaned_items:
            self._write_audit_log(cleaned_items)

    def _write_audit_log(self, items):
        """Append cleaned items to audit log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_size = sum(i["size"] for i in items)
        with open(AUDIT_LOG, "a") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"  CleanMyMac — {timestamp}\n")
            f.write(f"  Deleted {len(items)} items ({self._human_size(total_size)})\n")
            f.write(f"{'='*60}\n")
            for item in items:
                f.write(f"  [{item['category']}] {self._human_size(item['size']):>10}  {item['path']}\n")
            f.write("\n")

    def print_report(self, results, cleaned=False):
        """Print scan/clean report with full context."""
        total_size = 0
        total_items = 0
        safe_to_delete = 0
        safe_size = 0

        # Safety classification
        safe_categories = {"User Caches", "System Logs", "Homebrew Cache", "Trash", "Xcode Data"}
        review_categories = {"Old Downloads (>30 days)", "Docker"}
        cache_categories = {"Package Caches (pip/npm/yarn/HF)"}

        for category, items in results.items():
            if not items:
                continue
            cat_size = sum(i["size"] for i in items)
            total_size += cat_size
            total_items += len(items)

            # Determine safety level
            if category in safe_categories:
                safety = "🟢 SAFE to delete"
                safe_size += cat_size
                safe_to_delete += len(items)
            elif category in cache_categories:
                safety = "🟡 SAFE (will re-download when needed)"
                safe_size += cat_size
                safe_to_delete += len(items)
            elif category in review_categories:
                safety = "🔴 REVIEW before deleting"
            else:
                safety = "🟡 Review recommended"

            print(f"  ┌─ {category} — {self._human_size(cat_size)} ({len(items)} items)")
            print(f"  │  {safety}")
            print(f"  │")
            for item in items[:8]:  # Show top 8 per category
                age_str = f"{int(item['age_days'])}d ago" if item['age_days'] > 0 else "recent"
                status = ""
                if cleaned:
                    if item.get("cleaned"):
                        status = " ✅ removed"
                    elif "error" in item:
                        status = f" ❌ {item['error']}"
                print(f"  │  {self._human_size(item['size']):>10}  {age_str:<10} {item['name'][:45]}{status}")
                # Show path on next line for clarity
                print(f"  │  {'':>10}  {'':10} └─ {item['path']}")
            if len(items) > 8:
                remaining_size = sum(i["size"] for i in items[8:])
                print(f"  │  ... and {len(items) - 8} more ({self._human_size(remaining_size)})")
            print(f"  └{'─' * 60}")
            print()

        # Summary
        print("━" * 65)
        action = "Cleaned" if cleaned else "Found"
        if cleaned:
            # Only count items that were actually cleaned
            cleaned_size = sum(
                i["size"] for items in results.values() for i in items if i.get("cleaned")
            )
            cleaned_count = sum(
                1 for items in results.values() for i in items if i.get("cleaned")
            )
            failed_count = sum(
                1 for items in results.values() for i in items if "error" in i
            )
            skipped_count = sum(
                1 for items in results.values() for i in items if i.get("skipped")
            )
            print(f"  Cleaned: {self._human_size(cleaned_size)} ({cleaned_count} items removed)")
            if failed_count:
                print(f"  Failed:  {failed_count} items (permission denied — try with sudo)")
            if skipped_count:
                print(f"  Skipped: {skipped_count} items (excluded)")
        else:
            print(f"  {action}: {self._human_size(total_size)} total across {total_items} items")
            print()
            print(f"  🟢 Safe to delete (caches/logs/trash): {self._human_size(safe_size)} ({safe_to_delete} items)")
            print(f"  🔴 Needs review before deleting:       {self._human_size(total_size - safe_size)} ({total_items - safe_to_delete} items)")
            print()
            print(f"  To clean safe items:  cleanmymac clean")
            print(f"  Note: 'clean' skips Downloads and Docker — those require manual review.")
        print("━" * 65)
