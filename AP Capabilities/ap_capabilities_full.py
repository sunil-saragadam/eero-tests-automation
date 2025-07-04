import subprocess
import json
import os
import argparse

# --- MONITOR INTERFACE SETUP ---
def setup_monitor(base_iface="wlan0", mon_iface="mon0"):
    print(f"[INFO] Creating monitor interface '{mon_iface}' from '{base_iface}'...")
    subprocess.run(["iw", "dev", base_iface, "interface", "add", mon_iface, "type", "monitor"], check=True)
    subprocess.run(["ip", "link", "set", mon_iface, "up"], check=True)
    print(f"[INFO] Monitor interface '{mon_iface}' is up.")

# --- CAPTURE ---
def capture_pcap(interface, channel, duration, out_pcap):
    print(f"[INFO] Setting channel {channel} on {interface}")
    subprocess.run(["iw", interface, "set", "channel", str(channel)], check=True)

    print(f"[INFO] Capturing for {duration}s on {interface} -> {out_pcap}")
    subprocess.run(["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", out_pcap], check=True)

# --- EXTRACT SINGLE BEACON TO JSON ---
def extract_beacon_json(pcap_file, ssid, output_json):
    print(f"[INFO] Filtering beacon with SSID '{ssid}' and converting to JSON")
    cmd = [
        "tshark", "-r", pcap_file,
        "-T", "json", "--no-duplicate-keys",
        "-2", "-R", f'wlan.fc.type_subtype == 8 and wlan.ssid == "{ssid}"',
        "-c", "1"
    ]
    with open(output_json, "w") as f:
        subprocess.run(cmd, stdout=f, check=True)

# --- UTILITIES ---
def get_ext_tag_by_number(packet, target_number):
    try:
        ext_tags = packet["_source"]["layers"]["wlan.mgt"]["wlan.tagged.all"]["wlan.ext_tag"]
        if isinstance(ext_tags, dict):
            ext_tags = [ext_tags]
    except KeyError:
        return None
    for tag in ext_tags:
        if tag.get("wlan.ext_tag.number") == str(target_number):
            return tag
    return None

def get_nested(d, *keys):
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k)
        else:
            return None
    return d

# --- HE Decoder ---
def decode_he_mcs_map(hex_val):
    if not hex_val:
        return (0, None)
    bits = bin(int(hex_val, 16))[2:].zfill(16)
    max_nss, max_mcs = 0, 0
    for i in range(0, 16, 2):
        pair = bits[i:i+2]
        if pair == "00": max_nss += 1; max_mcs = max(max_mcs, 7)
        elif pair == "01": max_nss += 1; max_mcs = max(max_mcs, 9)
        elif pair == "10": max_nss += 1; max_mcs = max(max_mcs, 11)
    return (max_nss, max_mcs)

# --- EHT Decoder ---
def decode_eht_mcs_map(hex_string):
    if not hex_string:
        return {"rx": {}, "tx": {}, "max_nss": 0, "max_mcs": None}
    val = int(hex_string, 16)
    nibbles = [(val >> (4 * i)) & 0xF for i in range(6)]
    rx = {"0-9": nibbles[0], "10-11": nibbles[2], "12-13": nibbles[4]}
    tx = {"0-9": nibbles[1], "10-11": nibbles[3], "12-13": nibbles[5]}
    max_nss, max_mcs = 0, None
    for mcs_range, mcs_max in [("0-9", 9), ("10-11", 11), ("12-13", 13)]:
        r, t = rx[mcs_range], tx[mcs_range]
        if r > 0 or t > 0:
            max_nss = max(max_nss, r, t)
            max_mcs = max(max_mcs or 0, mcs_max)
    return {"rx": rx, "tx": tx, "max_nss": max_nss, "max_mcs": max_mcs}

# --- MAIN ANALYSIS ---
def analyze_json(packet):
    tag_he = get_ext_tag_by_number(packet, 35)
    tag_eht = get_ext_tag_by_number(packet, 108)

    print("\n===== HE Capabilities (802.11ax) =====")
    rx_he_80 = get_nested(tag_he, "Supported HE-MCS and NSS Set", "Rx and Tx MCS Maps <= 80 MHz", "wlan.ext_tag.he_mcs_map.rx_he_mcs_map_lte_80")
    rx_he_160 = get_nested(tag_he, "Supported HE-MCS and NSS Set", "Rx and Tx MCS Maps 160 MHz", "wlan.ext_tag.he_mcs_map.rx_he_mcs_map_160")
    print(f"HE 80MHz  -> {decode_he_mcs_map(rx_he_80)}")
    print(f"HE 160MHz -> {decode_he_mcs_map(rx_he_160)}")

    print("\n===== EHT Capabilities (802.11be) =====")
    eht_80 = get_nested(tag_eht, "Supported EHT-MCS and NSS Set", "wlan.eht.supported_eht_mcs_bss_set.eht_mcs_map_bw_le_80_mhz")
    eht_160 = get_nested(tag_eht, "Supported EHT-MCS and NSS Set", "wlan.eht.supported_eht_mcs_bss_set.eht_mcs_map_bw_eq_160_mhz")
    print(f"EHT 80MHz  -> {decode_eht_mcs_map(eht_80)}")
    print(f"EHT 160MHz -> {decode_eht_mcs_map(eht_160)}")

# --- CLI ENTRY ---
def main():
    parser = argparse.ArgumentParser(description="Capture and analyze AP HE/EHT capabilities.")
    parser.add_argument("-b", "--base-iface", required=True, help="e.g. wlan0")
    parser.add_argument("-m", "--mon-iface", default="mon0")
    parser.add_argument("-c", "--channel", required=True, type=int)
    parser.add_argument("-s", "--ssid", required=True)
    parser.add_argument("-t", "--duration", default=5, type=int)
    parser.add_argument("-p", "--pcap", default="cap.pcap")
    parser.add_argument("-j", "--json", default="cap.json")
    args = parser.parse_args()

    setup_monitor(args.base_iface, args.mon_iface)
    capture_pcap(args.mon_iface, args.channel, args.duration, args.pcap)
    extract_beacon_json(args.pcap, args.ssid, args.json)

    with open(args.json) as f:
        packets = json.load(f)
    if not packets:
        print("[!] No beacon packet found.")
        return

    analyze_json(packets[0])

if __name__ == "__main__":
    main()
