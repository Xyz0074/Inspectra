# INSPECTRA
**Agentless Windows Vulnerability and Network Scanner**

> Developed by: **Ansari Fardeen**, **Bushra Attarwala**, **Sayed Sajid Ali**  

---

## 📌 Overview

**INSPECTRA** is a GUI-based agentless security tool designed to scan Windows systems for potential vulnerabilities, open ports, and active network connections without requiring any installation on the target. It fetches real-time data from the NIST NVD CVE database using an API key to report known vulnerabilities in the system OS and running software.

Built with a visually intuitive interface using `customtkinter`, INSPECTRA empowers users to:
- Perform quick port scans (multi-threaded)
- Detect running processes and network activity
- Retrieve detailed system information
- Identify known CVEs for both OS and applications
- Generate and view a full scan report

---

## 💡 Features

- ✅ Agentless local scan — no need for remote installation
- 🚀 Multi-threaded port scanning (default: ports 1–1024)
- 🔐 CVE lookup using NVD API
- 📊 Real-time scan status and progress bar
- 💻 Modern GUI with easy navigation
- 📝 Auto-generated scan report (text format)

---

## 🛠️ Dependencies

Make sure to install the following Python packages before running the app:

```bash
pip install customtkinter psutil requests matplotlib Pillow
```

---

## ▶️ How to Run

1. Clone the repo or download the script:
    ```bash
    git clone https://github.com/your-org/inspectra.git
    cd inspectra
    ```

2. Launch the application:
    ```bash
    python inspectra.py
    ```

3. On launch, you’ll see:
    - **Welcome screen**
    - **Scan settings**: Choose port range, thread count, enable/disable CVE scan
    - **Progress page**: Visual scan updates
    - **Results dashboard**: With summaries, vulnerabilities, recommendations, and a button to open the report

---

## 📄 Output

- A detailed `.txt` report will be saved to the file you specify (default: `scan_report.txt`).
- Includes:
  - OS and IP info
  - Open ports with services
  - Running processes
  - Network connections
  - System details
  - Known CVEs (OS and top software)

---

## 🔐 Security Notes

- This tool uses the [NVD API](https://nvd.nist.gov/developers) — replace the default API key in `inspectra.py` if deploying publicly.
- Ensure you’re authorized to scan any system before use.

---

## 👨‍💻 Authors

- **Ansari Fardeen**
- **Bushra Attarwala**
- **Sayed Sajid Ali**

# OUTPUT
![op1](https://github.com/user-attachments/assets/49e5b311-eef2-4307-a02e-0a1292a5df38)
![op2](https://github.com/user-attachments/assets/adbd5bf2-7010-41b4-bc49-cd6ba3af1fb4)
![op3](https://github.com/user-attachments/assets/bdf26aef-5f87-4b32-85ad-f9694547d7b6)
![op4](https://github.com/user-attachments/assets/92b5ff8d-c78d-4f8e-ab9a-a773f0dffb1d)
![op5](https://github.com/user-attachments/assets/0af43a63-ac54-496f-9662-da24899b8902)
![op6](https://github.com/user-attachments/assets/1cd3c0bb-fe96-41ee-8a2e-9d2e93e0271a)
