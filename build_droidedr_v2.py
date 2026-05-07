#!/usr/bin/env python3
"""
DroidEDR v2 — Self-Contained Build Script
Handles SDK download, project scaffold, gradle fixes, APK build.
"""
import os, sys, subprocess, shutil, argparse, time, zipfile, urllib.request, stat

PROJECT_DIR  = os.path.dirname(os.path.abspath(__file__))
SDK_DIR      = os.path.join(PROJECT_DIR, "android-sdk")
CMDLINE_DIR  = os.path.join(SDK_DIR, "cmdline-tools", "latest")
SDKMANAGER   = os.path.join(CMDLINE_DIR, "bin", "sdkmanager")
ADB          = os.path.join(SDK_DIR, "platform-tools", "adb")
APK_OUT      = os.path.join(PROJECT_DIR, "app/build/outputs/apk/debug/app-debug.apk")
PACKAGE_NAME = "com.droidedr"
SDK_ZIP_URL  = "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
SDK_ZIP_PATH = os.path.join(SDK_DIR, "cmdline-tools.zip")

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║          DroidEDR v2 — Self-Contained Build System           ║
║          MITRE ATT&CK Mobile · Self-Healing · DNS VPN        ║
╚══════════════════════════════════════════════════════════════╝
"""

ROOT_BUILD_GRADLE = """buildscript {
    ext { kotlin_version = '1.9.22' }
    repositories { google(); mavenCentral() }
    dependencies {
        classpath 'com.android.tools.build:gradle:8.2.2'
        classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlin_version"
        classpath "com.google.devtools.ksp:com.google.devtools.ksp.gradle.plugin:1.9.22-1.0.17"
    }
}
task clean(type: Delete) { delete rootProject.buildDir }
"""

SETTINGS_GRADLE = """pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
        maven { url "https://jitpack.io" }
    }
}
rootProject.name = "DroidEDRv2"
include ':app'
"""

APP_BUILD_GRADLE = """plugins {
    id 'com.android.application'
    id 'kotlin-android'
    id 'com.google.devtools.ksp'
}
android {
    namespace 'com.droidedr'
    compileSdk 34
    defaultConfig {
        applicationId "com.droidedr"
        minSdk 26
        targetSdk 34
        versionCode 2
        versionName "2.0.0"
    }
    buildTypes {
        release { minifyEnabled false }
        debug   { debuggable true }
    }
    buildFeatures { compose true; buildConfig true }
    composeOptions { kotlinCompilerExtensionVersion '1.5.10' }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = '17'
        freeCompilerArgs += ['-opt-in=androidx.compose.material3.ExperimentalMaterial3Api']
    }
    packagingOptions {
        resources { excludes += ['/META-INF/{AL2.0,LGPL2.1}'] }
    }
}
dependencies {
    def composeBom = platform('androidx.compose:compose-bom:2024.02.00')
    implementation composeBom
    implementation 'androidx.compose.ui:ui'
    implementation 'androidx.compose.ui:ui-graphics'
    implementation 'androidx.compose.material3:material3'
    implementation 'androidx.compose.material:material-icons-extended'
    implementation 'androidx.compose.foundation:foundation'
    implementation 'androidx.core:core-ktx:1.12.0'
    implementation 'androidx.lifecycle:lifecycle-runtime-ktx:2.7.0'
    implementation 'androidx.lifecycle:lifecycle-viewmodel-compose:2.7.0'
    implementation 'androidx.activity:activity-compose:1.8.2'
    implementation 'androidx.navigation:navigation-compose:2.7.7'
    implementation 'androidx.work:work-runtime-ktx:2.9.0'
    implementation 'androidx.room:room-runtime:2.6.1'
    implementation 'androidx.room:room-ktx:2.6.1'
    ksp 'androidx.room:room-compiler:2.6.1'
    implementation 'org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3'
    implementation 'com.google.code.gson:gson:2.10.1'
    implementation 'androidx.security:security-crypto:1.1.0-alpha06'
}
"""

GRADLE_PROPERTIES = """org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8
android.useAndroidX=true
kotlin.code.style=official
android.nonTransitiveRClass=true
android.enableJetifier=true
"""

RES_FILES = {
    "app/src/main/res/values/strings.xml": """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">DroidEDR</string>
    <string name="edr_accessibility_label">DroidEDR Process Monitor</string>
    <string name="accessibility_description">DroidEDR monitors for threats.</string>
</resources>
""",
    "app/src/main/res/values/themes.xml": """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <style name="Theme.DroidEDR" parent="android:Theme.Material.Light.NoActionBar">
        <item name="android:windowBackground">@android:color/black</item>
    </style>
</resources>
""",
    "app/src/main/res/xml/device_admin.xml": """<?xml version="1.0" encoding="utf-8"?>
<device-admin><uses-policies>
    <limit-password/><watch-login/><reset-password/>
    <force-lock/><wipe-data/><encrypted-storage/>
</uses-policies></device-admin>
""",
    "app/src/main/res/xml/accessibility_service_config.xml": """<?xml version="1.0" encoding="utf-8"?>
<accessibility-service xmlns:android="http://schemas.android.com/apk/res/android"
    android:accessibilityEventTypes="typeWindowStateChanged"
    android:accessibilityFeedbackType="feedbackGeneric"
    android:notificationTimeout="100" />
""",
    "app/src/main/res/xml/network_security_config.xml": """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors><certificates src="system"/></trust-anchors>
    </base-config>
</network-security-config>
""",
    "app/src/main/res/xml/data_extraction_rules.xml": """<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup><exclude domain="file" path="baseline_v2.json"/></cloud-backup>
</data-extraction-rules>
""",
}

def run(cmd, cwd=None, check=True):
    print(f"  ▶ {cmd}")
    result = subprocess.run(cmd, cwd=cwd or PROJECT_DIR, shell=True,
                            text=True, env=os.environ)
    if check and result.returncode != 0:
        print(f"  ✗ Failed (exit {result.returncode})")
        sys.exit(1)
    return result

def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f: f.write(content)
    print(f"  ✓ {path}")

def step1_java():
    print("\n[1/5] Checking Java...")
    try:
        r = subprocess.run(["java", "-version"], capture_output=True, text=True)
        print(f"  ✓ {(r.stderr or r.stdout).splitlines()[0]}")
    except FileNotFoundError:
        print("  ✗ Java missing — run: sudo apt-get install -y openjdk-17-jdk")
        sys.exit(1)

def step2_sdk():
    print("\n[2/5] Setting up Android SDK...")
    if not os.path.exists(SDKMANAGER):
        os.makedirs(os.path.join(SDK_DIR, "cmdline-tools"), exist_ok=True)
        print("  Downloading SDK tools (~130MB)...")
        urllib.request.urlretrieve(SDK_ZIP_URL, SDK_ZIP_PATH)
        print("  Extracting...")
        with zipfile.ZipFile(SDK_ZIP_PATH, 'r') as z:
            z.extractall(os.path.join(SDK_DIR, "cmdline-tools"))
        extracted = os.path.join(SDK_DIR, "cmdline-tools", "cmdline-tools")
        latest    = os.path.join(SDK_DIR, "cmdline-tools", "latest")
        if os.path.exists(extracted):
            if os.path.exists(latest): shutil.rmtree(latest)
            os.rename(extracted, latest)
        if os.path.exists(SDK_ZIP_PATH): os.remove(SDK_ZIP_PATH)

    for f in [SDKMANAGER]:
        if os.path.exists(f):
            os.chmod(f, os.stat(f).st_mode | 0o111)

    os.environ["ANDROID_HOME"] = SDK_DIR
    os.environ["PATH"] = (os.path.join(CMDLINE_DIR,"bin") + ":" +
                          os.path.join(SDK_DIR,"platform-tools") + ":" +
                          os.environ["PATH"])

    subprocess.run(f"yes | {SDKMANAGER} --licenses", shell=True,
                   capture_output=True, env=os.environ)

    needed = []
    if not os.path.exists(os.path.join(SDK_DIR,"platform-tools","adb")):
        needed.append("platform-tools")
    if not os.path.exists(os.path.join(SDK_DIR,"platforms","android-34")):
        needed.append("platforms;android-34")
    if not os.path.exists(os.path.join(SDK_DIR,"build-tools","34.0.0")):
        needed.append("build-tools;34.0.0")
    if needed:
        print(f"  Installing {', '.join(needed)}...")
        run(f"{SDKMANAGER} " + " ".join(f'"{p}"' for p in needed))
    print("  ✓ SDK ready")

def step3_scaffold():
    print("\n[3/5] Scaffolding project...")
    app_dir  = os.path.join(PROJECT_DIR, "app")
    zip_path = os.path.join(PROJECT_DIR, "DroidEDRv2.zip")

    if not os.path.exists(app_dir):
        if not os.path.exists(zip_path):
            print("  ✗ DroidEDRv2.zip missing and app/ not found")
            sys.exit(1)
        print("  Extracting DroidEDRv2.zip...")
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(PROJECT_DIR)
        nested = os.path.join(PROJECT_DIR, "DroidEDRv2")
        if os.path.exists(nested):
            for item in os.listdir(nested):
                src = os.path.join(nested, item)
                dst = os.path.join(PROJECT_DIR, item)
                if not os.path.exists(dst):
                    shutil.move(src, dst)

    # Always overwrite gradle files
    write(os.path.join(PROJECT_DIR, "build.gradle"),      ROOT_BUILD_GRADLE)
    write(os.path.join(PROJECT_DIR, "settings.gradle"),   SETTINGS_GRADLE)
    write(os.path.join(PROJECT_DIR, "app/build.gradle"),  APP_BUILD_GRADLE)
    write(os.path.join(PROJECT_DIR, "gradle.properties"), GRADLE_PROPERTIES)
    write(os.path.join(PROJECT_DIR, "local.properties"),  f"sdk.dir={SDK_DIR}\n")

    for rel, content in RES_FILES.items():
        full = os.path.join(PROJECT_DIR, rel)
        if not os.path.exists(full):
            write(full, content)

    print("  ✓ Project scaffold complete")

def step4_build():
    print("\n[4/5] Building APK (3-8 min first run)...")
    gradlew = os.path.join(PROJECT_DIR, "gradlew")
    if not os.path.exists(gradlew):
        run("gradle wrapper --gradle-version 8.6 --distribution-type bin")
    if os.path.exists(gradlew):
        os.chmod(gradlew, os.stat(gradlew).st_mode | 0o111)
        cmd = "./gradlew assembleDebug --no-daemon --stacktrace"
    else:
        cmd = "gradle assembleDebug --no-daemon --stacktrace"
    run(cmd)
    if not os.path.exists(APK_OUT):
        print("  ✗ APK not found after build"); sys.exit(1)
    size = os.path.getsize(APK_OUT) / (1024*1024)
    print(f"  ✓ APK ready: {APK_OUT} ({size:.1f}MB)")
    return APK_OUT

def step5_install(apk, ip=None):
    print("\n[5/5] Installing on device...")
    adb = ADB if os.path.exists(ADB) else "adb"
    if ip:
        subprocess.run([adb,"connect",f"{ip}:5555"])
        time.sleep(2)
    r = subprocess.run([adb,"devices"], capture_output=True, text=True)
    if not any("\t" in l and "unauthorized" not in l for l in r.stdout.splitlines()):
        print("  ✗ No device. Connect USB or use --ip <device-ip>"); sys.exit(1)
    subprocess.run([adb,"uninstall",PACKAGE_NAME], capture_output=True)
    run(f"{adb} install -r -t {apk}")
    subprocess.run([adb,"shell","am","start","-n",f"{PACKAGE_NAME}/.ui.MainActivity"])
    print("  ✓ Installed and launched")

def main():
    print(BANNER)
    p = argparse.ArgumentParser()
    p.add_argument("--install",    action="store_true")
    p.add_argument("--ip",         help="Device IP for WiFi ADB")
    p.add_argument("--skip-build", action="store_true")
    args = p.parse_args()

    step1_java()
    step2_sdk()
    step3_scaffold()
    apk = step4_build() if not args.skip_build else APK_OUT
    if args.install: step5_install(apk, args.ip)

    print(f"""
  ══════════════════════════════════════════
  ✓ BUILD COMPLETE
  APK: {APK_OUT}

  To download from Codespaces:
  Right-click the file in the Explorer panel
  → Download
  ══════════════════════════════════════════
""")

if __name__ == "__main__":
    main()
