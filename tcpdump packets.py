import os
from scapy.all import *

monitor_card = 'wlan1'
ap_mac = '08:95:2A:6E:18:B8'
pack_s = '1000'
timeout = '300'
filter_rule = ' and type data and not type data subtype null'
#filter_rule = ''
dir_path = os.path.dirname(os.path.realpath(__file__))
file_name = dir_path + '/test.pcap'
print(file_name)

os.system('timeout ' + timeout + ' tcpdump -i ' + monitor_card + \
          ' -s ' + pack_s + ' -w ' + 'file_name' + ' -v' + ' ether host ' + ap_mac + \
          filter_rule)
scapy_pack = rdpcap(file_name)
scapy_pack.summary()