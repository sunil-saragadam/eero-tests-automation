import subprocess
import json
import os
import sys
import argparse
import csv

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

# --- JSON TAG EXTRACTION ---
def get_tag_by_number(packet, target_number):
    try:
        tags = packet["_source"]["layers"]["wlan.mgt"]["wlan.tagged.all"]["wlan.tag"]
        if isinstance(tags, dict):
            tags = [tags]
    except KeyError:
        return None
    for tag in tags:
        if tag.get("wlan.tag.number") == str(target_number):
            return tag
    return None

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

# --- DECODERS ---
def decode_he_mcs_map_verbose(hex_val):
    result = {"total_nss": 0, "max_mcs": None, "streams": []}
    if not hex_val:
        return result
    bits = bin(int(hex_val, 16))[2:].zfill(16)
    for i in range(16, 0, -2):
        stream_num = 8 - ((i // 2))
        pair = bits[i:i+2]
        if pair == "00": mcs = 7
        elif pair == "01": mcs = 9
        elif pair == "10": mcs = 11
        else: continue
        result["streams"].append({"nss": stream_num, "mcs_range": f"0–{mcs}"})
        result["total_nss"] += 1
        result["max_mcs"] = max(result["max_mcs"] or 0, mcs)
    return result

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

def decode_ht_rx_mcs_bitmask(rxbitmask_dict):
    supported_mcs_indices = []
    for key, hex_val in rxbitmask_dict.items():
        bit_range = key.split('.')[-1]
        if 'to' in bit_range:
            start, end = map(int, bit_range.split('to'))
        elif bit_range.isdigit():
            start = end = int(bit_range)
        else:
            continue
        bits = bin(int(hex_val, 16))[2:].zfill(end - start + 1)[::-1]
        for i, bit in enumerate(bits):
            if bit == "1": supported_mcs_indices.append(start + i)
    if not supported_mcs_indices:
        return {"total_nss": 0, "max_mcs": None, "supported_mcs_indices": []}
    max_mcs = max(supported_mcs_indices)
    total_nss = (max_mcs // 8) + 1
    return {"total_nss": total_nss, "max_mcs": max_mcs, "supported_mcs_indices": supported_mcs_indices}

def decode_vht_mcs_map(mcs_map_hex):
    if not mcs_map_hex:
        return {"total_nss": 0, "max_mcs": None, "streams": []}
    val = int(mcs_map_hex, 16)
    max_nss, max_mcs, streams = 0, 0, []
    for i in range(8):
        code = (val >> (i * 2)) & 0b11
        if code == 0b00: streams.append((i + 1, 7)); max_nss += 1; max_mcs = max(max_mcs, 7)
        elif code == 0b01: streams.append((i + 1, 8)); max_nss += 1; max_mcs = max(max_mcs, 8)
        elif code == 0b10: streams.append((i + 1, 9)); max_nss += 1; max_mcs = max(max_mcs, 9)
    return {"total_nss": max_nss, "max_mcs": max_mcs, "streams": [{"ss": ss, "mcs_range": f"0–{mcs}"} for ss, mcs in streams]}

# --- SAVE TO CSV ---
def save_capabilities_to_csv(data_rows, filename="wifi_caps.csv"):
    fieldnames = ["Mode", "Bandwidth", "Total NSS", "Max MCS", "short GI support"]
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in data_rows:
            writer.writerow(row)
    print(f"[INFO] Capability summary saved to {filename}")

# --- ANALYSIS ---
def analyze_json(packet, mface="mon0"):
    tag_he = get_ext_tag_by_number(packet, 35)
    tag_eht = get_ext_tag_by_number(packet, 108)
    tag_ht = get_tag_by_number(packet, 45)
    tag_vht = get_tag_by_number(packet, 191)
    csv_rows = []

    print("\n===== HT Capabilities (802.11n) =====")
    if tag_ht:
        rxbitmask = get_nested(tag_ht, "wlan.ht.mcsset", "wlan.ht.mcsset.rxbitmask")
        short_GI_20 = "20MHz" if get_nested(tag_ht, "wlan.ht.capabilities_tree", "wlan.ht.capabilities.short20") == "1" else ""
        short_GI_40 = "40MHz" if get_nested(tag_ht, "wlan.ht.capabilities_tree", "wlan.ht.capabilities.short40") == "1" else ""
        ht_map = decode_ht_rx_mcs_bitmask(rxbitmask)
        print(ht_map)
        csv_rows.append({
            "Mode": "HT", "Bandwidth": "20/40",
            "Total NSS": ht_map["total_nss"],
            "Max MCS": ht_map["max_mcs"],
            "short GI support": f"{short_GI_20} {short_GI_40}"
        })

    print("\n===== VHT Capabilities (802.11ac) =====")
    if tag_vht:
        rx_vht = get_nested(tag_vht, "wlan.vht.mcsset", "wlan.vht.mcsset.rxmcsmap")
        tx_vht = get_nested(tag_vht, "wlan.vht.mcsset", "wlan.vht.mcsset.txmcsmap")
        short_GI_80 = "80MHz" if get_nested(tag_vht, "wlan.vht.capabilities_tree", "wlan.vht.capabilities.short80") == "1" else ""
        short_GI_160 = "160MHz" if get_nested(tag_vht, "wlan.vht.capabilities_tree", "wlan.vht.capabilities.short160") == "1" else ""
        vht_rx = decode_vht_mcs_map(rx_vht)
        vht_tx = decode_vht_mcs_map(tx_vht)
        print("RX:", vht_rx)
        print("TX:", vht_tx)
        transmission = ["RX", "TX"]
        for i, map in enumerate([vht_rx, vht_tx]):
            csv_rows.append({
                "Mode": f"VHT {transmission[i]}", "Bandwidth": "20/40/80/160",
                "Total NSS": map["total_nss"],
                "Max MCS": map["max_mcs"],
                "short GI support": f"{short_GI_80} {short_GI_160}"
            })

    print("\n===== HE Capabilities (802.11ax) =====")
    rx_he_80 = get_nested(tag_he, "Supported HE-MCS and NSS Set", "Rx and Tx MCS Maps <= 80 MHz", "wlan.ext_tag.he_mcs_map.rx_he_mcs_map_lte_80")
    rx_he_160 = get_nested(tag_he, "Supported HE-MCS and NSS Set", "Rx and Tx MCS Maps 160 MHz", "wlan.ext_tag.he_mcs_map.rx_he_mcs_map_160")
    he_rx_80 = decode_he_mcs_map_verbose(rx_he_80)
    he_rx_160 = decode_he_mcs_map_verbose(rx_he_160)
    print("HE <=80MHz  ->", he_rx_80)
    print("HE 160MHz ->", he_rx_160)
    bwidths = ["<=80", "160"]
    for i, map in enumerate([he_rx_80, he_rx_160]):
        csv_rows.append({
            "Mode": "HE", "Bandwidth": bwidths[i],
            "Total NSS": map["total_nss"],
            "Max MCS": map["max_mcs"]
        })


    print("\n===== EHT Capabilities (802.11be) =====")
    eht_80 = get_nested(tag_eht, "Supported EHT-MCS and NSS Set", "wlan.eht.supported_eht_mcs_bss_set.eht_mcs_map_bw_le_80_mhz")
    eht_160 = get_nested(tag_eht, "Supported EHT-MCS and NSS Set", "wlan.eht.supported_eht_mcs_bss_set.eht_mcs_map_bw_eq_160_mhz")
    eht_320 = get_nested(tag_eht, "Supported EHT-MCS and NSS Set", "wlan.eht.supported_eht_mcs_bss_set.eht_mcs_map_bw_eq_320_mhz")
    eht80 = decode_eht_mcs_map(eht_80)
    eht160 = decode_eht_mcs_map(eht_160)
    eht320 = decode_eht_mcs_map(eht_320)
    print("EHT <=80MHz  ->", eht80)
    print("EHT 160MHz ->", eht160)
    print("EHT 320MHz ->", eht320)
    bwidths = ["<=80", "160", "320"]
    for i, map in enumerate([eht80, eht160, eht320]):
        csv_rows.append({
            "Mode": "EHT", "Bandwidth": bwidths[i],
            "Total NSS": map["max_nss"],
            "Max MCS": map["max_mcs"]
        })

    save_capabilities_to_csv(csv_rows)

    try:
        print("\n[INFO] monitor interface cleanup started.")
        subprocess.run(["iw", "dev", mface, "del"], check=True)
    except subprocess.SubprocessError as e:
        print(f"[ERROR] failed to close monitor interface {e}")
        sys.exit(1)
    finally:
        print("[INFO] monitor interface cleaned successfully.")

# # --- ANALYSIS ---
# def analyze_json(packet, mface="mon0"):
#     tag_he = get_ext_tag_by_number(packet, 35)
#     tag_eht = get_ext_tag_by_number(packet, 108)
#     tag_ht = get_tag_by_number(packet, 45)
#     tag_vht = get_tag_by_number(packet, 191)

#     csv_rows = []

#     print("\n===== HT Capabilities (802.11n) =====")
#     if tag_ht:
#         rxbitmask = get_nested(tag_ht, "wlan.ht.mcsset", "wlan.ht.mcsset.rxbitmask")
#         ht_res = decode_ht_rx_mcs_bitmask(rxbitmask)
#         print(ht_res)
#         csv_rows.append({
#             "Mode": "HT", "Bandwidth": "20/40",
#             "RX_NSS": ht_res["total_nss"],
#             "RX_Max_MCS": ht_res["max_mcs"],
#             "TX_NSS": ht_res["total_nss"],
#             "TX_Max_MCS": ht_res["max_mcs"]
#         })

#     print("\n===== VHT Capabilities (802.11ac) =====")
#     if tag_vht:
#         rx_vht = decode_vht_mcs_map(get_nested(tag_vht, "wlan.vht.mcsset", "wlan.vht.mcsset.rxmcsmap"))
#         tx_vht = decode_vht_mcs_map(get_nested(tag_vht, "wlan.vht.mcsset", "wlan.vht.mcsset.txmcsmap"))
#         print("RX:", rx_vht)
#         print("TX:", tx_vht)
#         csv_rows.append({
#             "Mode": "VHT", "Bandwidth": "20/40/80/160",
#             "RX_NSS": rx_vht["total_nss"],
#             "RX_Max_MCS": rx_vht["max_mcs"],
#             "TX_NSS": tx_vht["total_nss"],
#             "TX_Max_MCS": tx_vht["max_mcs"]
#         })

#     print("\n===== HE Capabilities (802.11ax) =====")
#     for bw, label in [("lte_80", "<=80MHz"), ("160", "160MHz")]:
#         rx_hex = get_nested(tag_he, "Supported HE-MCS and NSS Set", f"Rx and Tx MCS Maps {label}", f"wlan.ext_tag.he_mcs_map.rx_he_mcs_map_{bw}")
#         tx_hex = get_nested(tag_he, "Supported HE-MCS and NSS Set", f"Rx and Tx MCS Maps {label}", f"wlan.ext_tag.he_mcs_map.tx_he_mcs_map_{bw}")
#         rx_dec = decode_he_mcs_map_verbose(rx_hex)
#         tx_dec = decode_he_mcs_map_verbose(tx_hex)
#         print(f"HE {label} RX ->", rx_dec)
#         print(f"HE {label} TX ->", tx_dec)
#         csv_rows.append({
#             "Mode": "HE", "Bandwidth": label,
#             "RX_NSS": rx_dec["total_nss"],
#             "RX_Max_MCS": rx_dec["max_mcs"],
#             "TX_NSS": tx_dec["total_nss"],
#             "TX_Max_MCS": tx_dec["max_mcs"]
#         })

#     print("\n===== EHT Capabilities (802.11be) =====")
#     for bw, label in [("bw_le_80_mhz", "<=80MHz"), ("bw_eq_160_mhz", "160MHz"), ("bw_eq_320_mhz", "320MHz")]:
#         eht = decode_eht_mcs_map(get_nested(tag_eht, "Supported EHT-MCS and NSS Set", f"wlan.eht.supported_eht_mcs_bss_set.eht_mcs_map_{bw}"))
#         print(f"EHT {label} ->", eht)
#         csv_rows.append({
#             "Mode": "EHT", "Bandwidth": label,
#             "RX_NSS": sum(eht['rx'].values()),
#             "RX_Max_MCS": eht['max_mcs'],
#             "TX_NSS": sum(eht['tx'].values()),
#             "TX_Max_MCS": eht['max_mcs']
#         })

#     save_capabilities_to_csv(csv_rows)

#     try:
#         print("\n[INFO] monitor interface cleanup started.")
#         subprocess.run(["iw", "dev", mface, "del"], check=True)
#     except subprocess.SubprocessError as e:
#         print(f"[ERROR] failed to close monitor interface {e}")
#         sys.exit(1)
#     finally:
#         print("[INFO] monitor interface cleaned successfully.")

# --- CLI ENTRY ---
def main():
    parser = argparse.ArgumentParser(description="Capture and analyze AP HT/VHT/HE/EHT capabilities.")
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

    analyze_json(packets[0], args.mon_iface)

if __name__ == "__main__":
    main()
