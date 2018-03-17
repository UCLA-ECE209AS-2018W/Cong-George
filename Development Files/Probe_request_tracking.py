import os
import json
from scapy.all import *

monitor_card = 'wlan1mon'
ap_mac = '08:95:2a:6e:18:b8'
filter_rule1 = ' and type mgt and not subtype beacon'
file_name = 'probe_request.pcap'