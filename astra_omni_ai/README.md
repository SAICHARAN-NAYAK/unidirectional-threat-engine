# ASTRA OMNI // Unified Multimodal AI Enclave
> **Google Gemini 2.0 Pro + ChatGPT-6 Omni + Project Astra Live Vision & Voice**  
> *100% Free, Safe, Zero-Knowledge PBKDF2 Auth & Client-Side AES-GCM Encrypted.*

---

## 🌟 Overview

**ASTRA OMNI** is an ultra-modern, cross-platform AI workstation combining the signature capabilities of the three leading frontiers of AI into one seamless interface:

1. **✦ Google Gemini 2.0 Pro**:
   - Multimodal reasoning with photo, audio, and document uploads.
   - Real-time Google Search Grounding with interactive verified citations.
   - Interactive Artifact generation (HTML/JS/CSS, SVG, games, visualizations).
   - "Double-Check Fact" verification badge.

2. **⬡ ChatGPT-6 Omni**:
   - Deep Recursive "Thinking Process" / Chain-of-Thought (expandable step-by-step logic like o1/o3/GPT-6).
   - Reasoning depth selector: *Fast Heuristic*, *Deep Thought (o3)*, and *Rigorous Proof (o3-Max)*.
   - Collaborative Omni Canvas & Code Execution Sandbox.

3. **◎ Project Astra Live**:
   - Real-time continuous AR Camera Viewfinder with spatial target-tracking HUD.
   - Dynamic 3D/Canvas Audio Waveform Orb reacting to voice frequencies in real-time.
   - Low-latency continuous voice conversational loop via Web Speech Recognition & Natural Web Speech Synthesis.

---

## 🔐 Security & Privacy Architecture

- **Zero-Knowledge Authentication**: User master passwords are salted and hashed client-side with **PBKDF2-SHA256 (100,000 iterations)**. Your plaintext password is never stored or transmitted.
- **Multi-User Storage Isolation**: Each registered user has their own private, isolated database of conversations and configurations.
- **Web Crypto AES-GCM 256-bit Vault**: Optional passphrase locking of conversation archives using W3C Web Cryptography API.
- **Active Threat Guardrail**: Real-time heuristic filters blocking prompt injections, jailbreaks, and credential leaks.
- **Air-Gapped Privacy Mode**: One-click killswitch to disable outbound cloud requests and enforce purely local neural execution.

---

## 🚀 How to Deploy to Real-Life Web Platforms

### Option 1: 1-Click Deployment to Vercel (Recommended)
1. Fork or push this repository to your GitHub account:
   ```bash
   git add .
   git commit -m "feat: deploy Astra Omni AI"
   git push origin main
   ```
2. Go to [Vercel](https://vercel.com/) and click **Add New Project**.
3. Import your GitHub repository.
4. Set **Root Directory** to `astra_omni_ai`.
5. Click **Deploy**. Vercel will automatically use [`vercel.json`](./vercel.json) to serve your site with HTTPS, global CDN, and SPA routing!

---

### Option 2: 1-Click Deployment to Netlify
1. Log in to [Netlify](https://www.netlify.com/).
2. Select **Add new site** &rarr; **Import an existing project** (or drag and drop the `astra_omni_ai/` folder directly into Netlify Drop).
3. Set **Publish directory** to `astra_omni_ai`.
4. Click **Deploy Site**. Netlify will use [`netlify.toml`](./netlify.toml) to configure security headers and camera/mic permissions.

---

### Option 3: Free Deployment on GitHub Pages
This repository includes an automated GitHub Actions workflow (`.github/workflows/deploy_astra_omni.yml`).
1. Go to your GitHub repository **Settings** &rarr; **Pages**.
2. Under **Build and deployment** &rarr; **Source**, select **GitHub Actions**.
3. Any push to `main` will automatically deploy the site to:
   `https://<your-github-username>.github.io/<repo-name>/`

---

### Option 4: Run Locally on Desktop (Windows / Mac / Linux)
- **On Windows**: Double-click [`Launch_Astra_Omni.bat`](../Launch_Astra_Omni.bat) in the repository root.
- **Via Terminal (Any OS)**:
  ```bash
  cd astra_omni_ai
  python -m http.server 8090
  ```
  Open `http://localhost:8090` in Chrome, Edge, or Safari.

---

## 📱 How to Run as a Native Android App

The project contains a pre-configured Android Studio native container in [`android_studio_app/`](../android_studio_app/):

1. Open **Android Studio**.
2. Click **File** &rarr; **Open**, and select the folder:
   `android_studio_app`
3. Connect your Android phone via USB (with Developer Options & USB Debugging enabled) or choose an Android Emulator.
4. Click the green **Run** button (or press `Shift + F10`).
5. **Native Features**:
   - Hardware-accelerated WebView hosting the complete offline-capable Astra Omni web application.
   - Camera & Microphone permissions pre-configured for Project Astra Live Vision.
   - Native device haptic vibration feedback for threat guardrail and model actions.

---

## 🛠️ Free AI Engine Options (BYOK)

Astra Omni runs 100% free out of the box with zero keys required via its internal Autonomous Neural Simulation Engine. You can also connect free external APIs:
- **Google AI Studio (Gemini 2.0 Flash / Pro Free Tier)**: 15 Requests Per Minute free forever. Enter key in Settings &rarr; Free API Keys.
- **Local Ollama**: Run Llama 3, Mistral, or DeepSeek locally at `http://localhost:11434`.
- **Hugging Face Inference API**: Free open-source community models.

---

## 📄 License
MIT License. Free to use, modify, deploy, and distribute.
