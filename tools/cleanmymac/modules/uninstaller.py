"""
App uninstaller for macOS.
Finds app bundles and their associated files (caches, preferences, containers, etc.)
"""

import os
import subprocess
import shutil
from pathlib import Path
from modules.utils import human_size, dir_size


class AppUninstaller:
    """Find and remove apps with all their leftover files."""

    def __init__(self):
        self.home = Path.home()
        self.app_dirs = [
            Path("/Applications"),
            self.home / "Applications",
        ]

    def _human_size(self, size_bytes):
        return human_size(size_bytes)

    def _dir_size(self, path):
        return dir_size(path)

    def _get_bundle_id(self, app_path):
        """Get bundle identifier from Info.plist."""
        plist = app_path / "Contents" / "Info.plist"
        if plist.exists():
            try:
                out = subprocess.run(
                    ["defaults", "read", str(plist), "CFBundleIdentifier"],
                    capture_output=True, text=True, timeout=5
                )
                return out.stdout.strip()
            except (subprocess.TimeoutExpired, OSError):
                pass
        return None

    def list_apps(self, top_n=None):
        """List all installed apps with sizes."""
        print("📱 Installed Applications:\n")
        apps = []
        all_entries = []
        for app_dir in self.app_dirs:
            if not app_dir.exists():
                continue
            for entry in sorted(app_dir.iterdir()):
                if entry.suffix == ".app":
                    all_entries.append(entry)

        for i, entry in enumerate(all_entries):
            print(f"\r  ⏳ Scanning apps... {i+1}/{len(all_entries)}", end="", flush=True)
            size = self._dir_size(entry)
            bundle_id = self._get_bundle_id(entry) or "unknown"
            apps.append((entry.stem, size, bundle_id, entry))
        print()

        apps.sort(key=lambda x: x[1], reverse=True)
        display = apps[:top_n] if top_n else apps
        for name, size, bid, path in display:
            print(f"  {name:<35} {self._human_size(size):>10}  ({bid})")

        if top_n and len(apps) > top_n:
            print(f"\n  ... and {len(apps) - top_n} more (use --list to see all)")
        print(f"\n  Total: {len(apps)} apps")

    def _find_remnants(self, app_name, bundle_id):
        """Find all associated files for an app."""
        remnants = []
        name_lower = app_name.lower().replace(" ", "")

        # Patterns to search
        search_dirs = [
            (self.home / "Library" / "Application Support", "App Support"),
            (self.home / "Library" / "Caches", "Caches"),
            (self.home / "Library" / "Preferences", "Preferences"),
            (self.home / "Library" / "Logs", "Logs"),
            (self.home / "Library" / "Containers", "Containers"),
            (self.home / "Library" / "Group Containers", "Group Containers"),
            (self.home / "Library" / "Saved Application State", "Saved State"),
            (self.home / "Library" / "WebKit", "WebKit Data"),
            (self.home / "Library" / "HTTPStorages", "HTTP Storage"),
        ]

        for search_dir, label in search_dirs:
            if not search_dir.exists():
                continue
            for entry in search_dir.iterdir():
                entry_lower = entry.name.lower().replace(" ", "").replace(".", "")
                match = False
                # Match by bundle ID
                if bundle_id and bundle_id.lower() in entry.name.lower():
                    match = True
                # Match by app name
                elif name_lower in entry_lower:
                    match = True

                if match:
                    try:
                        size = self._dir_size(entry) if entry.is_dir() else entry.stat().st_size
                        remnants.append({
                            "path": str(entry),
                            "size": size,
                            "label": label,
                            "name": entry.name,
                        })
                    except (PermissionError, OSError):
                        pass

        return remnants

    def _find_launch_agents(self, app_name, bundle_id):
        """Find LaunchAgents associated with an app."""
        agents = []
        name_lower = app_name.lower().replace(" ", "")
        agent_dirs = [
            self.home / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
        ]
        for d in agent_dirs:
            if not d.exists():
                continue
            for plist in d.glob("*.plist"):
                plist_lower = plist.stem.lower().replace(" ", "").replace(".", "")
                match = False
                if bundle_id and bundle_id.lower() in plist.stem.lower():
                    match = True
                elif name_lower in plist_lower:
                    match = True
                if match:
                    try:
                        size = plist.stat().st_size
                        agents.append({
                            "path": str(plist),
                            "size": size,
                            "label": "LaunchAgent",
                            "name": plist.name,
                        })
                    except (PermissionError, OSError):
                        pass
        return agents

    def _is_running(self, app_name):
        """Check if an app is currently running."""
        try:
            out = subprocess.run(
                ["pgrep", "-fi", app_name],
                capture_output=True, text=True, timeout=5
            )
            return out.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def uninstall(self, app_name, dry_run=True):
        """Uninstall an app and find all remnants."""
        # Find the .app bundle
        app_path = None
        for app_dir in self.app_dirs:
            candidate = app_dir / f"{app_name}.app"
            if candidate.exists():
                app_path = candidate
                break
            # Fuzzy match
            if app_dir.exists():
                for entry in app_dir.iterdir():
                    if entry.suffix == ".app" and app_name.lower() in entry.stem.lower():
                        app_path = entry
                        break
            if app_path:
                break

        if not app_path:
            print(f"❌ App '{app_name}' not found in /Applications or ~/Applications")
            return

        # Check if running
        if self._is_running(app_path.stem):
            print(f"⚠️  {app_path.stem} is currently running.")
            if not dry_run:
                confirm = input("  Quit and uninstall? [y/N]: ").strip().lower()
                if confirm not in ("y", "yes"):
                    print("  Cancelled.")
                    return
                # Quit the app
                subprocess.run(
                    ["osascript", "-e", f'quit app "{app_path.stem}"'],
                    capture_output=True, timeout=10
                )
                import time
                time.sleep(2)

        bundle_id = self._get_bundle_id(app_path)
        app_size = self._dir_size(app_path)

        print(f"🗑️  Uninstall: {app_path.stem}")
        print(f"   Bundle ID: {bundle_id or 'unknown'}")
        print(f"   App size: {self._human_size(app_size)}")
        print()

        # Find remnants
        remnants = self._find_remnants(app_path.stem, bundle_id)
        launch_agents = self._find_launch_agents(app_path.stem, bundle_id)
        remnants.extend(launch_agents)

        total_remnant_size = sum(r["size"] for r in remnants)
        total_size = app_size + total_remnant_size

        print(f"  📦 App Bundle: {self._human_size(app_size)}")
        print(f"     {app_path}")
        print()

        if remnants:
            print(f"  📂 Associated Files ({len(remnants)} found, {self._human_size(total_remnant_size)}):")
            for r in sorted(remnants, key=lambda x: x["size"], reverse=True):
                print(f"     [{r['label']:<15}] {r['name']:<40} {self._human_size(r['size']):>8}")
            print()

        print("━" * 50)
        print(f"  Total reclaimable: {self._human_size(total_size)}")
        print("━" * 50)

        if dry_run:
            print("\n  ⚠️  Dry run — nothing was deleted.")
            print(f"  Run with --app \"{app_path.stem}\" (without --dry-run) to remove.")
        else:
            # Confirm before deletion
            confirm = input(f"\n  Delete {app_path.stem} and all remnants ({self._human_size(total_size)})? [y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                print("  Cancelled.")
                return

            # Actually delete
            print("\n  Removing...")
            errors = []

            # Remove app bundle
            try:
                shutil.rmtree(app_path)
                print(f"  ✅ Removed {app_path}")
            except (PermissionError, OSError) as e:
                errors.append(f"App bundle: {e}")
                print(f"  ❌ Failed: {app_path} — {e}")

            # Remove remnants
            for r in remnants:
                try:
                    p = Path(r["path"])
                    # For LaunchAgent/Daemon plists, try bootout first
                    if r.get("label") == "LaunchAgent" and p.suffix == ".plist":
                        service_label = p.stem
                        # Try to unload the service
                        subprocess.run(
                            ["launchctl", "bootout", f"gui/{os.getuid()}/{service_label}"],
                            capture_output=True, timeout=5
                        )
                        # Also try system-level
                        subprocess.run(
                            ["launchctl", "bootout", f"system/{service_label}"],
                            capture_output=True, timeout=5
                        )
                        print(f"  ⏹️  Unloaded {service_label}")
                    if p.is_dir():
                        shutil.rmtree(p)
                    else:
                        p.unlink()
                    print(f"  ✅ Removed {r['name']}")
                except (PermissionError, OSError) as e:
                    errors.append(f"{r['name']}: {e}")
                    print(f"  ❌ Failed: {r['name']} — {e}")

            print()
            if errors:
                print(f"  ⚠️  {len(errors)} items failed (may need sudo)")
            else:
                print(f"  ✅ Completely removed {app_path.stem} ({self._human_size(total_size)} freed)")
