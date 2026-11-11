# SPECTRA Community Telemetry & EEPROM Capture Database

[![Capture Validation](https://github.com/Pr0xyA-91/spectra-captures/actions/workflows/validate_and_index.yml/badge.svg)](https://github.com/Pr0xyA-91/spectra-captures/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Public community repository of diagnostic EEPROM dumps, hardware bus gateway vectors, and official service software ground-truth datasets for **SPECTRA Universal Hardware Diagnostics Suite**.

This database powers:
- **100% Precision Calibration**: Enables reverse-engineering of unknown beverage counters, maintenance countdowns, and operational thresholds across all Jura, Nivona, and Lamanti logic boards.
- **Offline Simulation & Emulation**: Provides exact hardware memory seeds (`MockJuraMachine`) for automated regression test suites.
- **Community-Driven Multi-Firmware Expansion**: Allows field technicians and reverse engineers to submit capture dumps from any appliance in seconds.

---

## 📂 Repository Structure

```
spectra-captures/
├── INDEX.json                             # Machine-readable catalog of all validated captures
├── captures/
│   ├── Jura/
│   │   ├── ENA_7/
│   │   │   └── spectra_capture_13500_20261111_101852.json
│   │   ├── A1/
│   │   ├── D4/
│   │   └── WE8/
│   ├── Nivona/
│   └── Lamanti/
├── scripts/
│   └── index_captures.py                  # Automated catalog builder & validation script
└── .github/
    ├── workflows/
    │   └── validate_and_index.yml         # Continuous integration validation on PR / commit
    └── ISSUE_TEMPLATE/
        └── new_capture.yml                # Web form for submitting new machine captures
```

---

## ☕ Verified Capture Catalog

| Manufacturer | Model Family | Article | Firmware | Words | Ground Truth | Capture File |
| :--- | :--- | :---: | :--- | :---: | :---: | :--- |
| **Jura** | **ENA 7** | `13500` | `EF634 V01.31` | 512 | ✅ Yes (J.O.E.) | [`captures/Jura/ENA_7/spectra_capture_13500_20261111_101852.json`](captures/Jura/ENA_7/spectra_capture_13500_20261111_101852.json) |

---

## 🚀 How to Capture & Submit a Machine Dump

### Option 1: Via SPECTRA Web UI
1. Connect your optical transceiver (or USB cable) to the machine and start SPECTRA:
   ```bash
   ./run_ui.sh
   ```
2. In the top bar, click **💾 EXPORT** $\to$ **Full Hardware Diagnostic Dump (.json)**.
3. *(Optional but Recommended)*: Attach your official J.O.E. app statistics export or service report text.
4. Click **Sweeping EEPROM & capturing hardware dump** to generate `spectra_capture_<MODEL>_<TIMESTAMP>.json`.
5. Submit via Pull Request or open a [New Capture Issue](https://github.com/Pr0xyA-91/spectra-captures/issues/new?template=new_capture.yml).

### Option 2: Via Headless CLI (`spectra_probe.py`)
```bash
python3 spectra_probe.py --port /dev/ttyUSB0 --joe /path/to/joe_export.csv --words 512
```

---

## 🛡️ Privacy & Safety Statement

All dumps collected in this repository are strictly diagnostic telemetry:
- **Zero Personally Identifiable Information (PII)**: Jura and Nivona EEPROM chips store exclusively integer cycle counters, hardware calibration ticks, date bitfields, and front-panel language string tables.
- **No Network or User Credentials**: Coffee machine microcontroller EEPROMs do not store names, passwords, GPS locations, IP addresses, or Wi-Fi keys.
- **Strict Read-Only Probe**: Capture tools use safe read commands (`TY:`, `TL:`, `IC:`, `RT:`, `RE:`) and never write (`WE:`, `WT:`, `DA:`) to machine memory.

---

## 📜 License

Licensed under the [MIT License](LICENSE). Contributions automatically fall under the same license.
