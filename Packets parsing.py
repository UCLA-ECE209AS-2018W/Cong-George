import os
import operator
import csv
import time
import sys

monitor_card = 'wlan1'
scan_s = '60'
file_name = 'packet_summary'
chosen_bssid = ''
file_path = os.system('pwd')
channel = '2'
BSSID = '08:95:2A:6E:18:B8'
devices = {}
data_pac = 0
ap_data = 0
dev_num = 0

# save 5-second scanning result to a csv file
print('Packet collecting...')
os.system('rm ' + file_name + '*')

os.system('timeout ' + scan_s + ' airodump-ng -w ' + file_name +
                                ' --output-format csv -I 5 --ignore-negative-one ' +
                                ' -c ' + channel + ' --bssid ' + BSSID + ' '
                                + monitor_card)

reader = csv.reader(open(file_name + '-01.csv'))
list_reader = list(reader)
print(list_reader)
ap_data = list_reader[2][-6]

for i, line in enumerate(list_reader):
    if i > 5 and len(line) > 0:
        print(line[0])
        print(line[-3])
        devices[line[0]] = line[-3]

dev_num = len(devices)

print(devices)
print(ap_data)
print(dev_num)
'''
# only extract AP info, dont need device info
filtered_r = [line for line in list_reader if (len(line) == len(list_reader[2]))]

# sort according to the pwr rating of APs
sortedlist = sorted(filtered_r, key=operator.itemgetter(8))

# filter out ap with incorrect info, fix format
for line in sortedlist:
    strip_item = line[8].replace(" ", '')
    if int(strip_item) < -1:
        # record the bssid of the AP with the strongest signal
        chosen_bssid = line[0].replace(" ", '')
        channel = line[3].replace(" ", '')
        SSID = line[-2].replace(" ", '')
        print("AP signal strength: " + strip_item)
        print("AP Mac address:" + chosen_bssid)
        print("channel: " + channel)
        print("SSID: " + SSID)
        break

# config adapter to focus on certain wifi frequency
channel_config = "iwconfig wlan1 channel " + channel
os.system(channel_config)
'''
