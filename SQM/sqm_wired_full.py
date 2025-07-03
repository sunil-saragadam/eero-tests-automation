import subprocess
import argparse
import os
import re
import json
import gzip
import sys
import serial
import time

# ------------------------- Utility Functions -------------------------
def run_cmd(cmd, logfile):
    print(f"\n[CMD] Running: {' '.join(cmd)}")
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    with open(logfile, 'a') as f:
        for line in iter(process.stdout.readline, ''):
            print(line.strip())
            f.write(line)
            sys.stdout.flush()

    process.stdout.close()
    process.wait()
    return process.returncode

def parse_iperf_output(logfile, direction):
    with open(logfile, 'r') as f:
        lines = f.readlines()

    for line in reversed(lines):
        if 'receiver' in line.lower() or 'sender' in line.lower():
            match = re.search(r'\d+\.?\d*\s+[KMG]bits/sec', line)
            if match:
                return f"{direction.capitalize()} throughput: {match.group(0)}"
    return f"{direction.capitalize()} throughput: Not found"

# ------------------------- Serial Console Helpers -------------------------
def serial_send(ser, cmd, delay=1):
    ser.write(cmd.encode() + b'\n')
    time.sleep(delay)
    return ser.read(ser.in_waiting).decode(errors='ignore')

def collect_cpu_stats_serial(serial_port, log_file, label, timeout=5):
    print(f"\n[CPU] Collecting CPU stats from {serial_port} ({label})...")
    try:
        ser = serial.Serial(port=serial_port, baudrate=115200, timeout=timeout, write_timeout=timeout)
        if not ser.is_open:
            ser.open()

        ser.write(b'\n')
        time.sleep(1)
        ser.flushInput()

        ser.write(b'mpstat -P ALL\n')
        time.sleep(2)

        output = ""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if ser.in_waiting:
                output += ser.read(ser.in_waiting).decode(errors="ignore")
            time.sleep(0.1)

        ser.write(b'\n')
        ser.close()

        with open(log_file, 'a') as f:
            f.write(f"\n===== CPU STATS ({label}) =====\n")
            f.write(output.strip() + "\n")

        print(f"[CPU] CPU stats collection complete from {serial_port} ({label})")
        print(output.strip())

    except Exception as e:
        print(f"[ERROR] Failed to collect CPU stats from {serial_port}: {e}")

# ------------------------- Crane Rate Configuration -------------------------
def apply_rate_limit_on_crane(upload_rate="100", download_rate="100", wface="eth9", serial_port="/dev/ttyUSB0", timeout=5):


    def extract_rates(content):
        ul = dl = None
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("tc class add dev") and "rate" in line:
                parts = line.split()
                try:
                    rate_index = parts.index("rate")
                    rate_val = parts[rate_index + 1]
                    iface = parts[4]
                    if iface == "$WANIFACE":
                        ul = rate_val.replace("mbit", "")
                    elif iface == "$IFB":
                        dl = rate_val.replace("mbit", "")
                except (ValueError, IndexError):
                    continue
        return ul, dl

    rate_script = f"""WANIFACE={wface}

IFB=br-lan

tc qdisc replace dev $WANIFACE root noqueue
tc qdisc del root dev $WANIFACE
tc qdisc add root dev $WANIFACE handle 1: htb default 1
tc class add dev $WANIFACE parent 1: classid 1:1 htb rate {upload_rate}mbit

tc qdisc replace dev $IFB root noqueue
tc qdisc del root dev $IFB
tc qdisc add root dev $IFB handle 1: htb default 1
tc class add dev $IFB parent 1: classid 1:1 htb rate {download_rate}mbit"""
    
    

    print(f"\n[Crane] Connecting to {serial_port}...")
    ser = serial.Serial(port=serial_port, baudrate=115200, timeout=timeout)
    time.sleep(1)
    ser.write(b'\n')
    time.sleep(1)

    # Read current rate.sh content
    print("[Crane] Checking existing rate.sh...")
    ser.write(b"cd /var\n")
    time.sleep(0.5)
    ser.write(b"cat rate.sh\n")
    time.sleep(1)
    existing = ser.read(ser.in_waiting).decode(errors='ignore')

    current_ul, current_dl = extract_rates(existing)
    print(f"[Crane] Existing rates: upload={current_ul} mbit, download={current_dl} mbit")

    if current_ul == str(upload_rate) and current_dl == str(download_rate):
        print("[Crane] Rates already match. Skipping rate.sh rewrite.")
        ser.close()
        return

    print(f"[Crane] Writing rate.sh with upload={upload_rate}, download={download_rate}...")
    serial_send(ser, "cd /var")
    serial_send(ser, "rm -f rate.sh")
    serial_send(ser, "cat > rate.sh <<'EOF'")
    for line in rate_script.strip().splitlines():
        serial_send(ser, line)
    serial_send(ser, "EOF", delay=1)

    print("[Crane] Applying rate.sh...")
    output = serial_send(ser, "sh rate.sh", delay=2)
    print(output)
    ser.close()
    print("[Crane] Rate limits applied successfully.\n")


# ------------------------- AP SQM Status Verification -------------------------
def verify_and_wait_for_sqm_enable(serial_port="/dev/ttyUSB1", timeout=5, ethx="eth0"):
    print(f"\n[AP] Connecting to AP on {serial_port} to verify SQM status...")
    ser = serial.Serial(port=serial_port, baudrate=115200, timeout=timeout)
    time.sleep(1)
    ser.write(b'\n')
    time.sleep(1)

    eth_cmd = f"tc qdisc show dev {ethx}"
    output_brlan = serial_send(ser, "tc qdisc show dev br-lan")
    output_ethx = serial_send(ser, eth_cmd)

    print("[AP] br-lan qdisc status:\n", output_brlan)
    print("[AP] ethX qdisc status:\n", output_ethx)

    sqm_disabled = any([
        "noqueue" in output_brlan.lower() or "pfifo_fast" in output_brlan.lower() or output_brlan.strip() == "",
        "noqueue" in output_ethx.lower() or "pfifo_fast" in output_ethx.lower() or output_ethx.strip() == ""
    ])

    if sqm_disabled:
        input("\n[SQM] SQM appears to be disabled. Please enable it using the admin app and press ENTER to continue...")
        print("[AP] Re-checking qdisc status...")
        output_brlan = serial_send(ser, "tc qdisc show dev br-lan")
        output_ethx = serial_send(ser, eth_cmd)
        print("[AP] Updated br-lan qdisc:\n", output_brlan)
        print("[AP] Updated ethX qdisc:\n", output_ethx)

    ser.close()
    print("[AP] SQM verification completed.\n")

# ------------------------- Main Test Runner -------------------------
def main():
    parser = argparse.ArgumentParser(description="Run iperf3 and flent rrul tests with SQM + rate control setup.")
    parser.add_argument("target_ip", help="Target host IP address")
    parser.add_argument("--iface", required=True, help="VRF interface (e.g. eth1)")
    parser.add_argument("--time", type=int, default=10, help="Test duration in seconds")
    parser.add_argument("--output", default="network_test.log", help="Log file name")
    parser.add_argument("--ethx", default="eth0", help="AP wan interface")
    parser.add_argument("--ul", default="75mbit", help="Upload rate for crane")
    parser.add_argument("--dl", default="50mbit", help="Download rate for crane")
    parser.add_argument("--wface", required=True, help="WAN interface of crane")
    parser.add_argument("--cp", required=True, help="Enter crane usb port name like /dev/ttyUSB0")
    parser.add_argument("--ap", required=True, help="Enter AP usb port name like /dev/ttyUSB0")
    args = parser.parse_args()

    log_file = args.output
    open(log_file, 'w').close()

    apply_rate_limit_on_crane(upload_rate=args.ul, download_rate=args.dl, wface=args.wface, serial_port=args.cp)
    verify_and_wait_for_sqm_enable(serial_port=args.ap, ethx=args.ethx)

    print("\nRunning iperf3 download test...")
    collect_cpu_stats_serial(args.ap, log_file, "Before iperf3 download")
    run_cmd(["./vrf_exec.bash", args.iface, "iperf3", "-c", args.target_ip, "-t", str(args.time), "-R"], log_file)
    print(parse_iperf_output(log_file, "download"))

    print("\nRunning iperf3 upload test...")
    collect_cpu_stats_serial(args.ap, log_file, "Before iperf3 upload")
    run_cmd(["./vrf_exec.bash", args.iface, "iperf3", "-c", args.target_ip, "-t", str(args.time)], log_file)
    print(parse_iperf_output(log_file, "upload"))

    print("\nRunning flent rrul test...")
    flent_file = "flent_rrul_result.flent.gz"
    collect_cpu_stats_serial(args.ap, log_file, "Before flent rrul")
    run_cmd(["./vrf_exec.bash", args.iface, "flent", "-H", args.target_ip, "rrul", "-l", str(args.time), "-t", "SQM-eden", "-o", flent_file], log_file)
    # print(parse_flent_latency_throughput(flent_file))
    print("\nPrinting raw flent result from file...")
    try:
        with open(flent_file, 'r') as f:
            for line in f:
                print(line.strip())
    except gzip.BadGzipFile:
        print("ERROR: Flent file is not actually gzipped. Try checking --gzip-output placement.")

if __name__ == "__main__":
    main()

# Example usage:
# python3 sunil/sqm_wired_full.py 192.168.215.25 --iface eth2 --time 5 --ethx eth0 --ul 100 --dl 100 --wface eth9 --cp /dev/ttyUSB0 --ap /dev/ttyUSB1

