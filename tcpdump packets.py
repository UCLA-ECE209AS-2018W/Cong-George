import os
import json
from scapy.all import *

monitor_card = 'wlan1mon'
ap_mac = '08:95:2a:6e:18:b8'
devices_data = {}
devices_null = {}
packet_summary = []
pck_device_sum = []
pack_sum_slice = {"device": 0, "null": 0, "data": 0, "payload": 0}
pack_s = '1000'
timeout = '30' # 3 mins
filter_rule1 = ' and type data and not type data subtype null'
filter_rule2 = ' and not type mgt subtype beacon'
filter_rule3 = ' type data'
dir_path = os.path.dirname(os.path.realpath(__file__))
file_name = 'test.pcap'
SGW_mac = ''
total_payload = 0
print(file_name)

slice_num = 4
sub_period = 10
total_periods = slice_num * sub_period

for j in range(slice_num):
    # collect 30 minutes of features
    for i in range(sub_period):
        print("Progress: " + str((1 - total_periods/(slice_num * sub_period))*100) + " percent")
        total_periods -= 1

        os.system('rm ' + file_name)
        '''os.system('timeout ' + timeout + ' tcpdump -i ' + monitor_card +
                  ' -s ' + pack_s + ' -w ' + file_name + ' -v' + ' ether host ' + ap_mac +
                  filter_rule2)'''
        os.system('timeout ' + timeout + ' tcpdump -i ' + monitor_card +
                  ' -s ' + pack_s + ' -w ' + file_name + ' -v' +
                  filter_rule3)
        scapy_pack = rdpcap(file_name)

        #addr1 -> RA, addr2 -> TA, addr3 -> SA
        for packets in scapy_pack:
            # if packets not corrupted
            if packets.haslayer("Dot11"):
                # if RA or TA is the target AP
                if packets.addr1 == ap_mac or packets.addr2 == ap_mac:

                    # if RA is the AP addr
                    if packets.addr1[:-3] == ap_mac[:-3]:

                        # if packet type is not Null Qos data and is not NULL data
                        if packets.subtype == 12 or packets.subtype == 4:
                            devices_null[packets.addr2] = devices_null.get(packets.addr2, 0) + 1
                        else:
                            devices_data[packets.addr2] = devices_data.get(packets.addr2, 0) + 1
                            total_payload += len(packets)

                    # if TA is the AP addr
                    elif packets.addr2[:-3] == ap_mac[:-3]:

                        # if only last byte differ from AP, then SA is SGW
                        if packets.addr3[:-3] == ap_mac[:-3]:
                            SGW_mac = packets.addr3

                        # if TA is targeted AP, then record SA (RA could be ff:ff:ff:ff)
                        if packets.subtype == 12 or packets.subtype == 4:
                            devices_null[packets.addr3] = devices_null.get(packets.addr3, 0) + 1
                        else:
                            devices_data[packets.addr3] = devices_data.get(packets.addr3, 0) + 1
                            total_payload += len(packets)

        total_data = sum(devices_data.values())
        total_null = sum(devices_null.values())

        # count the number of devices
        dev_num = len(devices_data)
        for device in devices_data.keys():
            if device not in pck_device_sum and device[:-3] != ap_mac[:-3]:
                pck_device_sum.append(device)

        for device in devices_null.keys():
            if device not in devices_data and device[:-3] != ap_mac[:-3]:
                dev_num += 1
            if device not in pck_device_sum and device[:-3] != ap_mac[:-3]:
                pck_device_sum.append(device)

        print("Null data pack count: " + str(total_null))
        print(devices_null)

        print("data pack count: " + str(total_data))
        print(devices_data)

        print("SGW MAC address: " + SGW_mac)
        print("device number: " + str(dev_num))

        # build feature vectors
        pack_sum_slice["device"] = len(pck_device_sum)
        pack_sum_slice["null"] += total_null
        pack_sum_slice["data"] += total_data
        pack_sum_slice["payload"] += total_payload/total_data

        # reinitialize
        devices_data.clear()
        devices_null.clear()
        total_payload = 0

    # insert last 30-min feature in summary
    packet_summary.append(copy.copy(pack_sum_slice))
    print(pack_sum_slice)
    print(pck_device_sum)
    pack_sum_slice["device"] = 0
    pack_sum_slice["null"] = 0
    pack_sum_slice["data"] = 0
    pack_sum_slice["payload"] = 0
    pck_device_sum = []

print(packet_summary)
with open("output.txt", 'w') as file:
    file.write(json.dumps(packet_summary))