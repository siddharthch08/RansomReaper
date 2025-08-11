# 🛡 RansomReaper --> Ransomware Detector (Hybrid GUI + Heuristics)

##  Introduction  
**RansomReaper** is a **cross-platform ransomware early detection tool** that combines a **Tkinter GUI** with **heuristics-based detection logic**.  
It monitors specified folders in **real-time** for suspicious file activity and alerts you when potential ransomware behavior is detected.  

Unlike aggressive tools that quarantine on any file change, this detector uses **smart heuristics** to minimize false positives while still responding quickly to genuine threats.  

---

##  Features  

- **Real-time Monitoring**  
  Monitors one or more folders using the `watchdog` library.

- ** Heuristics-Based Detection**  
  - **Event Rate** — Detects unusually high number of file changes in a short time.  
  - **Extension Changes** — Flags mass renames like `.txt → .locked`.  
  - **Entropy Checks** — Detects encrypted-looking files.  
  - **Honeypot Triggers** — Special folder that, if modified, triggers a high-confidence alert.  

- **Process Mapping**  
  Identifies processes that are modifying watched files using `psutil`.

- **Optional Auto-Response**  
  - **Auto-Quarantine** — Moves suspicious files to a secure quarantine folder.  
  - **Auto-Kill** — Terminates processes suspected of ransomware activity.  

- **GUI + CLI Modes**  
  - **GUI Mode** — Tkinter interface with Start/Stop controls and live activity logs.  
  - **Headless CLI Mode** — Ideal for servers or remote monitoring.  

- **Simulation Mode**  
  Safe testing mode that simulates ransomware-like activity.

- **Incident Reports**  
  Saves detailed incident logs including suspected processes, files, and detection stats.

---

##  Requirements  

Install dependencies:  
```bash
pip install -r requirements.txt
```
**Requirements:**
- `watchdog`
- `psutil`
- `tkinter` (bundled with most Python installations)

---

##  Usage  

### **GUI Mode (Default)**  
```bash
python RansomReaper.py
```

### **Headless Mode**  
```bash
python RansomReaper.py --nogui
```

### **Simulate Ransomware Activity (Safe Test)**  
```bash
python RansomReaper.py --simulate --simulate-dir ./sim_target
```

### **Custom Watch Paths**  
```bash
python RansomReaper.py --watch "C:/MyFolder" "/home/user/projects"
```

### **Enable Auto-Quarantine & Auto-Kill ( Dangerous)**  
```bash
python RansomReaper.py --auto-quarantine --auto-kill
```

---

##  Project Structure  

```
.
├── RansomReaper.py   # Main script
├── requirements.txt           # Dependencies
├── README.md                  # Documentation
├── .gitignore                 # Ignore unnecessary files
├── logs/                      # Runtime logs
├── incident_reports/          # Generated incident reports
└── quarantine/                # Quarantined files
```

---

##  How Detection Works  

1. **File Monitoring** → Watches for file creation, modification, movement, and renames.  
2. **Heuristic Analysis** → Every few seconds, calculates:  
   - Number of events  
   - Extension changes count  
   - Average entropy of modified files  
3. **Suspicious Behavior Trigger** → If thresholds are exceeded, an alert is triggered.  
4. **Response Actions** → Logs the event, creates an incident report, optionally kills processes and quarantines files.  

---

##  Disclaimer  

This tool is provided **for educational and defensive purposes only**.  
- Do **NOT** use it to target or interfere with systems without permission.  
- Always test in a controlled environment before using in production.  
- Auto-kill and auto-quarantine modes can disrupt legitimate processes and should be enabled **only with caution**.  
- No security tool is 100% effective — use as part of a layered defense strategy with backups and endpoint protection.

---

##  License  
MIT License © 2025 — You are free to use, modify, and distribute this tool with attribution.
