import subprocess
import time
import os
import signal
import argparse
import sys

# --- setup monitor ---
def setup_monitor(base_iface, mon_iface):
    '''Create and bring up a monitor interface.'''
    print(f"[INFO] Setting up monitor interface '{mon_iface}' from '{base_iface}'...")
    subprocess.run(["iw", "dev", base_iface, "interface", "add", mon_iface, "type", "monitor"], check=True)
    subprocess.run(["ip", "link", "set", mon_iface, "up"], check=True)
    print(f"[INFO] Monitor interface '{mon_iface}' is up.")

# --- start sniffing ---
def start_sniffer(interface, channel, pcap_file):
    '''Start tshark capture on the given interface.'''
    print(f"[INFO] Setting channel {channel} on {interface}")
    subprocess.run(["iw", interface, "set", "channel", str(channel)], check=True)
    print(f"[INFO] Starting tshark on {interface}, writing to {pcap_file}...")
    cmd = [
        "tshark",
        "-i", interface,
        "-w", pcap_file
    ]
    return subprocess.Popen(cmd, preexec_fn=os.setsid)

# --- stop sniffing ---
def stop_sniffer(proc):
    '''Terminate the tshark process group.'''
    print("[INFO] Stopping tshark capture...")
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception as e:
        print(f"[WARN] Failed to stop sniffer cleanly: {e}")

# --- create client method ---
def create_client_cli(mgr, radio, ssid, bssid, passwd, security):
    '''Start a client from cli using lanforge script'''
    CREATE_STATION_CMD = [
        "python3", "/home/lanforge/lanforge-scripts/py-scripts/create_station.py",
        "--mgr", mgr,
        "--radio", radio,
        "--ssid", ssid,
        "--passwd", passwd,
        "--bssid", bssid,
        "--security", security,
        "--num_stations", "1"
    ]
    return subprocess.run(CREATE_STATION_CMD, check=True)


def main():
    parser = argparse.ArgumentParser(
        description="Automate WiFi security test: sniff & client connect"
    )
    parser.add_argument("-b", "--base-iface", default="wlan0", help="Base wireless interface (e.g. wlan0)")
    parser.add_argument("-m", "--monitor-iface", default="mon0", help="Monitor interface name to create")
    parser.add_argument("-c", "--channel", required=True, help="Wireless channel to set on monitor interface")
    parser.add_argument("-p", "--pcap-out", default="/tmp/connection.pcap", help="Path to write captured pcap")
    parser.add_argument("--mgr", required=True, help="LANforge manager IP")
    parser.add_argument("--radio", required=True, help="Radio interface (e.g. 1.1.wiphy1)")
    parser.add_argument("--ssid", required=True, help="SSID to connect to")
    parser.add_argument("--bssid", default="DEFAULT", help="BSSID to connect to")
    parser.add_argument("--passwd", required=True, help="Password for the SSID")
    parser.add_argument("--security", required=True, help="Security type (e.g. wpa2, wpa3)")

    args = parser.parse_args()

    try:
        setup_monitor(args.base_iface, args.monitor_iface)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to set up monitor interface: {e}")
        sys.exit(1)

    sniffer = start_sniffer(args.monitor_iface, args.channel, args.pcap_out)
    time.sleep(1)

    try:
        print("[INFO] Running client creation command...")
        create_client_cli(
            mgr=args.mgr,
            radio=args.radio,
            ssid=args.ssid,
            bssid=args.bssid,
            passwd=args.passwd,
            security=args.security
        )
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Client creation failed: {e}")
        stop_sniffer(sniffer)
        sys.exit(1)
    finally:
        stop_sniffer(sniffer)

    print(f"[INFO] Capture available at {args.pcap_out}")


if __name__ == "__main__":
    main()
