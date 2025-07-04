
# SQM Test Automation

This repository automates Smart Queue Management (SQM) testing for eero Access Points using serial console access. It supports automated rate configuration, SQM status verification, performance testing (iperf3, flent), and CPU usage logging.

---

## 🔧 Setup

### Hardware Setup

* One eero AP (console on `/dev/ttyUSB2`)
* One crane (console on `/dev/ttyUSB0`)
* One AP in station mode (optional)

---

## 🚀 Test Flow

1. **Rate Configuration (Crane)**
   Set upload/download limits via `rate.sh` over serial.

2. **Verify SQM Toggle (AP)**
   Check SQM status and wait for manual toggle if disabled.

3. **Run Tests + Monitor CPU**
   Run iperf3 and flent tests while collecting CPU stats.

## ✋ Manual Step

SQM must be toggled via the eero admin app. The script will pause and wait for user input before continuing when required.

---

## 🚀 Usage

```bash
python3 sqm_test_run.py [target_ip] --iface eth1 --time 10 --output output.log \
  --ethx eth0 --ul 75 --dl 50 --wface eth9 \
  --cp /dev/ttyUSB0 --ap /dev/ttyUSB2
```

---

### 🔍 Arguments

#### Positional:

* `target_ip` – IP address of the iperf3/flent server

#### Optional flags:

| Option     | Description                                    |
| ---------- | ---------------------------------------------- |
| `--iface`  | VRF interface to run tests (e.g., `eth1`)      |
| `--time`   | Duration of each test in seconds               |
| `--output` | Log file name (default: `network_test.log`)    |
| `--ethx`   | WAN interface name on the AP (e.g., `eth0`)    |
| `--ul`     | Upload rate in Mbit/s for crane (e.g., `75`)   |
| `--dl`     | Download rate in Mbit/s for crane (e.g., `50`) |
| `--wface`  | WAN interface name on crane (e.g., `eth9`)     |
| `--cp`     | Serial port for crane (e.g., `/dev/ttyUSB0`)   |
| `--ap`     | Serial port for AP (e.g., `/dev/ttyUSB2`)      |

---

## 📄 Output

* All logs including command outputs and CPU stats are written to the specified log file.
* Flent `.flent.gz` files are saved for offline plotting or parsing.

## 🧪 Sample Output

```
[Crane] Existing rates: upload=75 mbit, download=50 mbit
[AP] SQM appears to be DISABLED. Enable it via the admin app and press ENTER to re-check...
Running iperf3 download test...
Running iperf3 upload test...
Running flent rrul test...
```

