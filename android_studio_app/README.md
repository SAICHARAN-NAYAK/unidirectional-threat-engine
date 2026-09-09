# CYBERSHIELD Android App // HTML WebView Edition

Native Android Studio application for the **CYBERSHIELD Unidirectional IP Cyber Threat Detection Enclave**.

---

## How to Open in Android Studio

1. Double-click [`Open_In_Android_Studio.bat`](../Open_In_Android_Studio.bat) in the repository root.
   - Or open **Android Studio**, click **File** &rarr; **Open**, and choose this folder:
     `C:\Users\saich\.gemini\antigravity-ide\scratch\unidirectional-threat-engine\android_studio_app`
2. Allow Android Studio to sync Gradle dependencies.
3. Select your device or emulator (e.g. `Pixel_10_Pro`) from the device dropdown.
4. Click **Run** (or press `Shift + F10`).

---

## Project Structure

```
android_studio_app/
├── build.gradle.kts                 # Root project build configuration
├── settings.gradle.kts               # Gradle settings
├── local.properties                 # Points to local Android SDK
├── app/
│   ├── build.gradle.kts             # App dependencies (WebKit, Material, SwipeRefresh)
│   └── src/main/
│       ├── AndroidManifest.xml      # Permissions: INTERNET, ACCESS_NETWORK_STATE, VIBRATE
│       ├── java/com/cybershield/threatengine/
│       │   ├── MainActivity.kt      # Hardware-accelerated WebView & back navigation
│       │   └── WebAppInterface.kt   # JavaScriptInterface bridge (haptics, toasts, telemetry)
│       ├── assets/                  # Bundled HTML/CSS/JS web application
│       │   ├── index.html           # Responsive mobile SOC interface
│       │   ├── styles.css           # Dark enterprise cybersecurity palette
│       │   └── app.js               # Client controller with dual online/offline engine
│       └── res/                     # Android layouts, colors, themes, adaptive icons
```

---

## Key Features

1. **Native HTML WebView Architecture**:
   - Bundles the complete CYBERSHIELD frontend into `app/src/main/assets/`.
   - Full hardware acceleration, DOM storage, and responsive touch gestures.

2. **Dual Online / Offline Mode**:
   - **Online Mode**: Connects to the local threat engine (`http://10.0.2.2:8080` from emulator) or public tunnel (`https://lower-watts-new-mistakes.trycloudflare.com`).
   - **Air-Gapped Standalone Simulation**: If no server is reachable, the app automatically runs an internal simulation engine so you can test and demonstrate all 6 tabs with zero dependencies.

3. **Android Native Bridge (`WebAppInterface`)**:
   - `AndroidBridge.showToast(message)`: Displays native Android system toasts.
   - `AndroidBridge.triggerHaptic(severity)`: Triggers physical device haptic vibrations on critical and high threat alerts.
   - `AndroidBridge.getDeviceTelemetry()`: Passes battery, network type, and hardware model to the interface.

4. **Endpoint Switcher**:
   - Tap the **OPTICAL RX ONLY (⚙️)** badge in the top bar to switch between Emulator (`10.0.2.2:8080`), Public Tunnel, or Offline Simulation.
