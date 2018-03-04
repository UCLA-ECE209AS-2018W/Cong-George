from scapy.all import *

file = "tmp.pcap"

packets = rdpcap(file)
probe_signature = {"probe":[], "htcap":[], "httag":[], "htmcs":[], "vhtcap":[], "vhtrxmcs":[], "vhttxmcs":[],
             "extcap":[], "txpow":[], "wps":[]}
assoc_signature = {"probe":[], "htcap":[], "httag":[], "htmcs":[], "vhtcap":[], "vhtrxmcs":[], "vhttxmcs":[],
             "extcap":[], "txpow":[], "wps":[]}

# SSID packet[Dot11Elt][0]
# Rates packet[Dot11Elt][1]
# RSRates packet[Dot11Elt][2]
# DSet packet[Dot11Elt][3]

for packet in packets:
    if packet.haslayer("Dot11") and packet.haslayer("Dot11ProbeReq"):
        # get probe identifiers
        for field in packet["Dot11Elt"]:
            # get probe
            if field.ID == 221:
                probe_signature["probe"].append([field.ID, (field.info[0:3], field.info[3])])
            else:
                probe_signature["probe"].append(field.ID)

            # get htcap and httag and htmcs
            if field.ID == 45:
                probe_signature["htcap"].append(field.info[0:2])
                probe_signature["httag"].append(field.info[3])
                probe_signature["htmcs"].append(field.info[4:8])

            # get vht related signatures
            if field.ID == 191:
                probe_signature["vhtcap"].append(field.info[0:4])
                probe_signature["vhtrxmcs"].append(field.info[4:8])
                probe_signature["vhttmcs"].append(field.info[8:12])


