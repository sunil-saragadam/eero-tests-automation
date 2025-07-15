## 📡 AP HT/VHTHE/EHT Capability Analyzer

This script captures Wi-Fi beacon frames from a specified SSID and extracts **802.11n (HT)**, **802.11ac (VHT)**, **802.11ax (HE)** and **802.11be (EHT)** capabilities, such as:

* Maximum spatial streams (NSS)
* Maximum MCS support
* Bandwidth support (80 MHz, 160 MHz)

It uses `tshark` and `iw` to sniff, filter, and decode capabilities from beacon frames.

---

### ✅ Features

* Creates a monitor-mode interface on demand
* Captures a beacon frame on a specified channel
* Extracts **802.11n (HT)**, **802.11ac (VHT)**, **HE (tag 35)** and **EHT (tag 108)** extended capabilities
* Decodes MCS/NSS per bandwidth
* Human-readable output

---

### ⚙️ Requirements

* `iw`
* `tshark` (v4.0+ recommended)
* Root access (for monitor mode and packet capture)
* Python 3.6+

---

### 🚀 Usage

```bash
sudo python3 analyze_ap_capabilities.py \
  -b wlan0 \
  -m mon0 \
  -c 36 \
  -s "candela18 - 0270-2G-1" \
  -t 5 \
  -p scan.pcap (optional) \
  -j beacon.json (optiona)
```

#### Arguments:

| Argument | Description                                   |
| -------- | --------------------------------------------- |
| `-b`     | Base interface name (e.g., `wlan0`)           |
| `-m`     | Monitor interface to create (default: `mon0`) |
| `-c`     | Wi-Fi channel to tune to                      |
| `-s`     | SSID to filter beacon frames                  |
| `-t`     | Capture duration in seconds (default: 5)      |
| `-p`     | Output `.pcap` filename                       |
| `-j`     | Output `.json` filename                       |

---

### 🧪 Output Example

```
===== HE Capabilities (802.11ax) =====
HE 80MHz  -> (2, 9)
HE 160MHz -> (1, 9)

===== EHT Capabilities (802.11be) =====
EHT 80MHz  -> {'rx': {'0-9': 2, '10-11': 2, '12-13': 0}, 'tx': {'0-9': 2, '10-11': 2, '12-13': 2}, 'max_nss': 2, 'max_mcs': 13}
EHT 160MHz -> {'rx': {'0-9': 1, '10-11': 1, '12-13': 0}, 'tx': {'0-9': 1, '10-11': 1, '12-13': 1}, 'max_nss': 1, 'max_mcs': 13}
```

---

### 🧹 Cleanup

To remove the monitor interface manually:

```bash
sudo iw dev mon0 del
```
