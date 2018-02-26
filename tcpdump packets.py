import os
from scapy.all import *

monitor_card = 'wlan1'
ap_mac = '08:95:2a:6e:18:b8'
devices_data = {}
devices_null = {}
total_data = 0
total_null = 0
total_devices = 0
pack_s = '1000'
timeout = '60'
filter_rule1 = ' and type data and not type data subtype null'
filter_rule2 = ' and not type mgt subtype beacon'
filter_rule3 = ' type data'
dir_path = os.path.dirname(os.path.realpath(__file__))
file_name = 'test.pcap'
SGW_mac = ''
print(file_name)

os.system('rm ' + file_name)
'''os.system('timeout ' + timeout + ' tcpdump -i ' + monitor_card +
          ' -s ' + pack_s + ' -w ' + file_name + ' -v' + ' ether host ' + ap_mac +
          filter_rule2)'''
os.system('timeout ' + timeout + ' tcpdump -i ' + monitor_card +
          ' -s ' + pack_s + ' -w ' + file_name + ' -v' + 
          filter_rule3)
scapy_pack = rdpcap(file_name)
scapy_pack.summary()

#addr1 -> RA, addr2 -> TA, addr3 -> SA
for packets in scapy_pack:
    if packets.haslayer("Dot11"):
        # if RA or TA is the target AP
        if packets.addr1 == ap_mac or packets.addr2 == ap_mac:
            # if RA is the AP addr
            if packets.addr1 == ap_mac:
                # if packet type is not Null Qos data and is not NULL data
                if packets.subtype == 12 or packets.subtype == 4:
                    devices_null[packets.addr2] = devices_null.get(packets.addr2, 0) + 1
                else:
                    devices_data[packets.addr2] = devices_data.get(packets.addr2, 0) + 1
            # if TA is the AP addr
            elif packets.addr2 == ap_mac:
                # if only last byte differ from AP, then SA is SGW
                if packets.addr3[:-3] == ap_mac[:-3]:
                    SGW_mac = packets.addr3

                # if TA is targeted AP, then record SA (RA could be ff:ff:ff:ff)
                if packets.subtype == 12 or packets.subtype == 4:
                    devices_null[packets.addr3] = devices_null.get(packets.addr3, 0) + 1
                else:
                    devices_data[packets.addr3] = devices_data.get(packets.addr3, 0) + 1

total_data = sum(devices_data.values())
total_null = sum(devices_null.values())

total_devices = sum(devices_data.keys())
for device in total_null:
    if device not in total_data:
        total_devices += 1

print("Null data pack count: " + total_null)
print(devices_null)

print("data pack count: " + total_data)
print(devices_data)

print("SGW MAC address: " + SGW_mac)
print("device number: " + total_devices)
