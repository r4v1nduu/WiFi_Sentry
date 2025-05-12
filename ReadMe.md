# WiFi Sentry

**WiFi Sentry** is a lightweight, open-source Wi-Fi security scanner designed for real-time analysis of public Wi-Fi networks. Built for non-technical users and cybersecurity learners alike, this tool provides instant visibility into common network threats like ARP spoofing, DNS hijacking, rogue access points, and weak encryption.

---

## 🔐 Key Features

- **One-click Scan:** Quickly analyze the current Wi-Fi network in under 10 seconds.
- **Risk Summary Dashboard:** Visual indicators (Low/Medium/High) across:
  - Network Encryption
  - ARP Table Anomalies
  - DNS Manipulation
  - BSSID Patterns
  - SSID Spoofing
- **Detailed Technical Output:** View findings from each module in expandable logs.
- **Modular Architecture:** Each scanner module runs independently for faster performance.
- **Passive & Non-Invasive:** No active probing or internet-based lookups.
- **Fully Offline Capable:** No data sent outside the device.
- **Simple GUI:** Built with `tkinter` for cross-platform compatibility.

---

## 🛠️ How to Build the App (EXE for Windows)

### ✅ Prerequisites

- Python 3.10 or later
- Pip (Python package manager)
- PyInstaller

### 🔧 Step-by-Step Build Instructions

1. **Clone this repo:**

   ```bash
   git clone https://github.com/yourusername/WiFiSentry.git
   cd WiFiSentry
   ```

2. **Install required dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Build EXE with PyInstaller (Windows only):**

   ```bash
   pyinstaller --noconfirm --onefile --windowed --name WiFiSentry ^
   --add-data "configs;WiFiSentry/configs" ^
   --add-data "gui;WiFiSentry/gui" ^
   --add-data "modules;WiFiSentry/modules" ^
   --add-data "utils;WiFiSentry/utils" ^
   main_gui.py
   ```

4. **Find your executable:**

- Output EXE will be in the dist/ folder as WiFiSentry.exe
