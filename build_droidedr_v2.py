#!/usr/bin/env python3
"""
DroidEDR v2 — One-Click Build & Install
========================================
Builds the APK and installs via ADB (USB or TCP).

Usage:
  python3 build_droidedr_v2.py          # Build debug APK
  python3 build_droidedr_v2.py --release # Build release APK
  python3 build_droidedr_v2.py --install # Build + install via ADB
  python3 build_droidedr_v2.py --install --ip 192.168.1.100  # ADB over WiFi
"""

import os
import sys
import subprocess
import shutil
import argparse
import platform
import time

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
APK_DEBUG   = os.path.join(PROJECT_DIR, "app/build/outputs/apk/debug/app-debug.apk")
APK_RELEASE = os.path.join(PROJECT_DIR, "app/build/outputs/apk/release/app-release.apk")
PACKAGE_NAME = "com.droidedr"

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║          DroidEDR v2 — Android EDR Build System              ║
║          MITRE ATT&CK Mobile · Self-Healing · DNS VPN        ║
╚══════════════════════════════════════════════════════════════╝
"""

def run(cmd, cwd=None, check=True):
    print(f"  ▶ {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    result = subprocess.run(
        cmd, cwd=cwd or PROJECT_DIR,
        capture_output=False, text=True,
        shell=isinstance(cmd, str)
    )
    if check and result.returncode != 0:
        print(f"  ✗ Command failed (exit {result.returncode})")
        sys.exit(1)
    return result

def check_prerequisites():
    print("\n[1/5] Checking prerequisites...")
    
    # Java
    try:
        result = subprocess.run(["java", "-version"], capture_output=True, text=True)
        version_line = result.stderr or result.stdout
        print(f"  ✓ Java: {version_line.splitlines()[0] if version_line else 'detected'}")
    except FileNotFoundError:
        print("  ✗ Java not found. Install JDK 17+")
        sys.exit(1)
    
    # Android SDK
    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not android_home:
        if platform.system() == "Darwin":
            candidate = os.path.expanduser("~/Library/Android/sdk")
        elif platform.system() == "Windows":
            candidate = os.path.join(os.environ.get("LOCALAPPDATA",""), "Android", "Sdk")
        else:
            candidate = os.path.expanduser("~/Android/Sdk")
        if os.path.exists(candidate):
            android_home = candidate
            os.environ["ANDROID_HOME"] = android_home
    
    if android_home and os.path.exists(android_home):
        print(f"  ✓ Android SDK: {android_home}")
    else:
        print("  ✗ Android SDK not found. Set ANDROID_HOME or install Android Studio.")
        sys.exit(1)
    
    return android_home

def setup_local_properties(android_home):
    print("\n[2/5] Configuring local.properties...")
    local_props = os.path.join(PROJECT_DIR, "local.properties")
    sdk_path = android_home.replace("\\", "\\\\")
    with open(local_props, "w") as f:
        f.write(f"sdk.dir={sdk_path}\n")
    print(f"  ✓ Written: {local_props}")

def build_apk(release=False):
    print(f"\n[3/5] Building {'release' if release else 'debug'} APK...")
    
    # Make gradlew executable on Unix
    gradlew = os.path.join(PROJECT_DIR, "gradlew")
    gradlew_bat = os.path.join(PROJECT_DIR, "gradlew.bat")
    
    if platform.system() == "Windows":
        gradle_cmd = [gradlew_bat]
    else:
        if os.path.exists(gradlew):
            os.chmod(gradlew, 0o755)
            gradle_cmd = [gradlew]
        else:
            # Fall back to system gradle
            gradle_cmd = ["gradle"]
    
    task = "assembleRelease" if release else "assembleDebug"
    run(gradle_cmd + [task, "--stacktrace", "--no-daemon"])
    
    apk_path = APK_RELEASE if release else APK_DEBUG
    if os.path.exists(apk_path):
        size_mb = os.path.getsize(apk_path) / (1024 * 1024)
        print(f"  ✓ APK built: {apk_path} ({size_mb:.1f} MB)")
        return apk_path
    else:
        print(f"  ✗ APK not found at {apk_path}")
        sys.exit(1)

def get_adb():
    """Find ADB binary."""
    android_home = os.environ.get("ANDROID_HOME", "")
    candidates = [
        os.path.join(android_home, "platform-tools", "adb"),
        os.path.join(android_home, "platform-tools", "adb.exe"),
        "adb",
    ]
    for c in candidates:
        if shutil.which(c) or os.path.exists(c):
            return c
    print("  ✗ ADB not found. Is platform-tools installed?")
    sys.exit(1)

def connect_adb_wifi(adb, ip, port=5555):
    print(f"\n  Connecting ADB over WiFi to {ip}:{port}...")
    run([adb, "connect", f"{ip}:{port}"])
    time.sleep(2)

def install_apk(apk_path, adb, ip=None):
    print(f"\n[4/5] Installing APK...")
    
    if ip:
        connect_adb_wifi(adb, ip)
    
    # Check devices
    result = subprocess.run([adb, "devices"], capture_output=True, text=True)
    devices = [l for l in result.stdout.splitlines() if "\t" in l and "unauthorized" not in l]
    
    if not devices:
        print("  ✗ No ADB devices found. Connect device via USB or specify --ip for WiFi.")
        print("\n  To enable ADB:")
        print("  1. Settings → About Phone → tap 'Build Number' 7 times")
        print("  2. Settings → Developer Options → USB Debugging ON")
        sys.exit(1)
    
    print(f"  ✓ Found {len(devices)} device(s)")
    
    # Uninstall existing (ignore error if not installed)
    subprocess.run([adb, "uninstall", PACKAGE_NAME], capture_output=True)
    
    # Install
    run([adb, "install", "-r", "-t", apk_path])
    print(f"  ✓ Installed {PACKAGE_NAME}")

def grant_permissions(adb):
    print("\n[5/5] Granting permissions...")
    
    permissions = [
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    ]
    
    for perm in permissions:
        result = subprocess.run(
            [adb, "shell", "pm", "grant", PACKAGE_NAME, perm],
            capture_output=True, text=True
        )
        status = "✓" if result.returncode == 0 else "⚠"
        print(f"  {status} {perm.split('.')[-1]}")
    
    # Launch app
    print("\n  Launching DroidEDR...")
    run([adb, "shell", "am", "start", "-n", f"{PACKAGE_NAME}/.ui.MainActivity"])

def print_post_install_guide():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                   POST-INSTALL SETUP                         ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  REQUIRED MANUAL STEPS (one-time):                           ║
║                                                              ║
║  1. ACCESSIBILITY SERVICE                                    ║
║     Settings → Accessibility → DroidEDR → Enable            ║
║                                                              ║
║  2. VPN PERMISSION (DNS Shield)                              ║
║     App will prompt on first launch → Allow                  ║
║                                                              ║
║  3. DEVICE ADMIN (Self-Healing)                              ║
║     Settings → Device Admin → DroidEDR → Activate           ║
║                                                              ║
║  4. BATTERY OPTIMIZATION EXEMPTION                           ║
║     Settings → Battery → DroidEDR → Don't Optimize          ║
║                                                              ║
║  5. USAGE STATS PERMISSION                                   ║
║     Settings → Privacy → Usage Access → DroidEDR → Allow    ║
║                                                              ║
║  MITRE COVERAGE:                                             ║
║    ✓ 35 Detection Rules                                      ║
║    ✓ LotL / DNS / DHCP / Brute Force / Remote Access         ║
║    ✓ 8 CVEs (CVE-2021 through CVE-2026)                      ║
║    ✓ Self-Healing + Boot Persistence                         ║
║    ✓ 7-Day Behavioral Baseline                               ║
║    ✓ DNS VPN Interception (DoH)                              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="DroidEDR v2 Build & Install")
    parser.add_argument("--release", action="store_true", help="Build release APK")
    parser.add_argument("--install", action="store_true", help="Install via ADB after build")
    parser.add_argument("--ip", help="Device IP for ADB over WiFi")
    parser.add_argument("--skip-build", action="store_true", help="Skip build, just install existing APK")
    args = parser.parse_args()
    
    android_home = check_prerequisites()
    setup_local_properties(android_home)
    
    if args.skip_build:
        apk_path = APK_RELEASE if args.release else APK_DEBUG
        if not os.path.exists(apk_path):
            print(f"  ✗ APK not found: {apk_path}. Run without --skip-build first.")
            sys.exit(1)
    else:
        apk_path = build_apk(release=args.release)
    
    if args.install:
        adb = get_adb()
        install_apk(apk_path, adb, ip=args.ip)
        grant_permissions(adb)
    
    print_post_install_guide()
    print(f"\n  APK: {apk_path}\n")

if __name__ == "__main__":
    main()
