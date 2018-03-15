from scapy.all import *

class signature:
    def __init__(self, type):
        if type in ["probe", "assoc"]:
            self.type = type
        else:
            print("wrong data type!")
            raise ValueError

        # change member type from list[] to string'' for bitwise comparison later
        self.probe_id = [] # this needs to be a list!
        self.htcap = ''
        self.httag = ''
        self.htmcs = ''
        self.vhtcap = ''
        self.vhtrxmcs = ''
        self.vhttxmcs = ''
        self.txpow = ''
        self.excap = ''

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


def build_WifiSig(file_name, mac_addr, ignore_mac=0):
    # create a instance of wifi signature
    wifi_signature = wifi_sig(mac_addr) if ignore_mac == 0 else wifi_sig("ff:ff:ff:ff:ff:ff")

    # read in packets
    packets = rdpcap(file_name)
    print("start to build device wifi signature...")
    for packet in packets:
        if packet.haslayer("Dot11") and (packet.addr2 == wifi_signature.mac_addr or ignore_mac == 1):
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
                            wifi_signature.probe_sig.htcap=(field.info[0:2])
                            wifi_signature.probe_sig.httag=(field.info[2])
                            wifi_signature.probe_sig.htmcs=(field.info[3:7])

                        # get vht related signatures
                        if field.ID == 191:
                            wifi_signature.probe_sig.vhtcap=(field.info[0:4])
                            wifi_signature.probe_sig.vhtrxmcs=(field.info[4:8])
                            wifi_signature.probe_sig.vhttxmcs=(field.info[8:12])

                        # get txpow related signatures
                        if field.ID == 33:
                            wifi_signature.probe_sig.txpow=(field.info)

                        # get txpow related signatures
                        if field.ID == 127:
                            wifi_signature.probe_sig.excap=(field.info)

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
                            wifi_signature.ass_sig.htcap=(field.info[0:2])
                            wifi_signature.ass_sig.httag=(field.info[3])
                            wifi_signature.ass_sig.htmcs=(field.info[4:8])

                        # get vht related signatures
                        if field.ID == 191:
                            wifi_signature.ass_sig.vhtcap=(field.info[0:4])
                            wifi_signature.ass_sig.vhtrxmcs=(field.info[4:8])
                            wifi_signature.ass_sig.vhttmcs=(field.info[8:12])

                        # get txpow related signatures
                        if field.ID == 33:
                            wifi_signature.ass_sig.txpow=(field.info)

                        # get excap related signatures
                        if field.ID == 127:
                            wifi_signature.ass_sig.excap=(field.info)

                    except IndexError:
                        break

    # print out signature
    print("wifi signature build finish!")
    return wifi_signature

"""
if __name__ == "__main__":
    file = "ass_test2.pcap"
    target_mac = "7c:50:49:27:33:e3"
    new_sig = build_WifiSig(file, target_mac)
    new_sig.display()
"""
