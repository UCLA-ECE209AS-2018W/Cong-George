import os
import sys
import pickle
from scapy.all import *

# import my own files function
sys.path.append(os.path.abspath("/root/PycharmProjects/EE209AS-Embedded-System-Security"))
from device_signature import *

def clear_sig_database(file):
    if os.path.exists(file):
        with open(file, 'rb') as rfp:
            database = pickle.load(rfp)

        # clear out everything
        database = {}

        with open(file, 'wb') as wfp:
            pickle.dump(database, wfp)
    # if there is no database
    else:
        raise Exception("file not exist")

def save_new_sig(file, wifi_sig, device_name, device_type):
    if os.path.exists(file):
        with open(file, 'rb') as rfp:
            database = pickle.load(rfp)

        # add the new wifi signature object
        # create wifi signature tuple: (device_type, signature object)
        database[device_name] = (device_type, wifi_sig)

        with open(file, 'wb') as wfp:
            pickle.dump(database, wfp)
    # if there is no database
    else:
        database = {device_name: (device_type, wifi_sig)}
        with open(file, 'wb') as wfp:
            pickle.dump(database, wfp)


def load_sig_database(file):
    if os.path.exists(file):
        with open(file, 'rb') as rfp:
            database = pickle.load(rfp)

            if len(database) == 0:
                print("Warning: database empty!")

        return database
    else:
        raise Exception("no database file!")


def display_database(file):
    if os.path.exists(file):
        with open(file, 'rb') as rfp:
            database = pickle.load(rfp)

        for name, value in database.items():
            print("device name: " + name)
            print("device type: " + str(value[0]))
            print("device wifi sigature: ")
            value[1].display()
    else:
        raise Exception("no database file!")


if __name__ == "__main__":
    sig_file = "Googlehome.pcap"
    target_mac = "f4:f5:d8:a4:7b:d4"
    device_name = "Googlehome"
    device_type = 2  # 0: phone, 1: laptop, 2: IotDevice, 3: other
    database_file = "signature_database.p"

    new_sig = build_WifiSig(sig_file, target_mac)
    save_new_sig(database_file, new_sig, device_name, device_type)
    display_database(database_file)
