class sig_record:
    def __init__(self, name, type, mac, time=""):
        self.name = name
        self.type = type
        self.mac = mac
        self.time = time  # time this device appear in network


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
        for keys, value in self.active_stats.items():
            print("current period stats: ")
            print(str(value) + keys)

    def all_dev_display(self):
        for dev in self.all_dev_list:
            print(dev.name + "," + self.predef_type[dev.type] + "," + dev.mac + "," + dev.time)
