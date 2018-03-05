from scapy.all import *

file = "ass_test2.pcap"
target_mac = "7c:50:49:27:33:e3"

'''
probe_signature = {"probe":[], "htcap":[], "httag":[], "htmcs":[], "vhtcap":[], "vhtrxmcs":[], "vhttxmcs":[],
             "extcap":[], "txpow":[], "excap":[]}
assoc_signature = {"assoc":[], "htcap":[], "httag":[], "htmcs":[], "vhtcap":[], "vhtrxmcs":[], "vhttxmcs":[],
             "extcap":[], "txpow":[], "excap":[]}
wifi_signature = {"mac_addr": target_mac, "probe": probe_signature, "assoc": assoc_signature,
                  "has_probe": 0, "has_assoc": 0}
'''

class signature:
    def __init__(self, type):
        if type in ["probe", "assoc"]:
            self.type = type
        else:
            print("wrong data type!")
            raise ValueError

        self.probe_id = []
        self.htcap = []
        self.httag = []
        self.htmcs = []
        self.vhtcap = []
        self.vhtrxmcs = []
        self.vhttxmcs = []
        self.extcap = []
        self.txpow = []
        self.excap = []

class wifi_sig:
    sig_count = 0

    def __init__(self, mac_addr):
        self.mac_addr = mac_addr
        self.has_probe = 0
        self.has_ass = 0
        self.ass_sig = signature("assoc")
        self.probe_sig = signature("probe")

    def display(self):
        print("mac_address = " + self.mac_addr)
        print("has probe = " + str(self.has_probe))
        print("has ass = " + str(self.has_ass))
        print(self.ass_sig.__dict__)
        print(self.probe_sig.__dict__)

def build_WifiSig(file_name, mac_addr):
    # create a instance of wifi signature
    wifi_signature = wifi_sig(mac_addr)

    # read in packets
    packets = rdpcap(file_name)
    print("start to build device wifi signature...")
    for packet in packets:
        if packet.haslayer("Dot11") and packet.addr2 == wifi_signature.mac_addr:
            print("find target device, building signature...")
            if packet.haslayer("Dot11ProbeReq") and wifi_signature.has_probe == 0:
                # set has probe bit
                wifi_signature.has_probe = 1

                # get probe identifiers
                for i in range(100):
                    try:
                        field = packet[Dot11Elt][i]
                        # get probe
                        if field.ID == 221:
                            wifi_signature.probe_sig.probe_id.append([field.ID, (field.info[0:3], field.info[3])])
                        else:
                            wifi_signature.probe_sig.probe_id.append(field.ID)

                        # get htcap and httag and htmcs
                        if field.ID == 45:
                            wifi_signature.probe_sig.htcap.append(field.info[0:2])
                            wifi_signature.probe_sig.httag.append(field.info[2])
                            wifi_signature.probe_sig.htmcs.append(field.info[3:7])

                        # get vht related signatures
                        if field.ID == 191:
                            wifi_signature.probe_sig.vhtcap.append(field.info[0:4])
                            wifi_signature.probe_sig.vhtrxmcs.append(field.info[4:8])
                            wifi_signature.probe_sig.vhttmcs.append(field.info[8:12])

                        # get txpow related signatures
                        if field.ID == 33:
                            wifi_signature.probe_sig.txpow.append(field.info)

                        # get txpow related signatures
                        if field.ID == 127:
                            wifi_signature.probe_sig.excap.append(field.info)

                    except IndexError:
                        break

            if packet.haslayer("Dot11AssoReq") and wifi_signature.has_ass == 0:
                # set has assoc bit
                wifi_signature.has_ass = 1

                # get probe identifiers
                for i in range(100):
                    try:
                        field = packet[Dot11Elt][i]
                        # get probe
                        if field.ID == 221:
                            wifi_signature.ass_sig.probe_id.append([field.ID, (field.info[0:3], field.info[3])])
                        else:
                            wifi_signature.ass_sig.probe_id.append(field.ID)

                        # get htcap and httag and htmcs
                        if field.ID == 45:
                            wifi_signature.ass_sig.htcap.append(field.info[0:2])
                            wifi_signature.ass_sig.httag.append(field.info[3])
                            wifi_signature.ass_sig.htmcs.append(field.info[4:8])

                        # get vht related signatures
                        if field.ID == 191:
                            wifi_signature.ass_sig.vhtcap.append(field.info[0:4])
                            wifi_signature.ass_sig.vhtrxmcs.append(field.info[4:8])
                            wifi_signature.ass_sig.vhttmcs.append(field.info[8:12])

                        # get txpow related signatures
                        if field.ID == 33:
                            wifi_signature.ass_sig.txpow.append(field.info)

                        # get txpow related signatures
                        if field.ID == 127:
                            wifi_signature.ass_sig.excap.append(field.info)

                    except IndexError:
                        break

    # print out signature
    print("wifi signature build finish!")
    return wifi_signature


if __name__ == "__main__":
    new_sig = build_WifiSig(file, target_mac)
    new_sig.display()