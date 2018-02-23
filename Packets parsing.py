import os
from scapy.all import *

dir_path = os.path.dirname(os.path.realpath(__file__))
file_name = dir_path + '/test.pcap'
devices = []

scapy_pack = rdpcap(file_name)
scapy_pack.summary()