import sys
import os
import pickle
from device_signature import *
import signature_database_create as sdc


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
    sig_database = sdc.load_sig_database(db_file)

    # start to calculate ham distance with the target sig vs. item in db
    min_ham = 10000  # a very large number
    min_sig = "unknown"
    for sig in sig_database.keys():
        ham_dist = ham_distance(sig_target, sig_database[sig][1])
        # take note the min ham item in database
        if ham_dist < min_ham:
            min_ham = ham_dist
            min_sig = sig

    # if the minimum haming distance is smaller than a threshold
    if min_ham < 10:
        ret = (min_sig, sig_database[min_sig][0])
        return ret
    else:
        print("unclassified device")
        ret = ("unknown", -1)
        return ret


if __name__ == "__main__":
    db_file = "signature_database.p"
    file1 = "huaweiPhone.pcap"
    target_mac1 = "44:6e:e5:9d:72:a3"
    file2 = "iphone7plus.pcap"
    target_mac2 = "7c:50:49:27:33:e3"
    file3 = "mac.pcap"
    target_mac3 = "c4:b3:01:c0:d7:55"
    file4 = "Googlehome.pcap"
    target_mac4 = "f4:f5:d8:a4:7b:d4"
    file5 = "iphone7.pcap"
    target_mac5 = "18:65:90:7f:2e:e2"
    file6 = "iphone6.pcap"
    target_mac6 = "58:7f:57:bf:57:fb"
    file7 = "iphone7plus2.pcap"
    target_mac7 = "00:db:70:6a:3a:ec"
    new_sig_huawei = build_WifiSig(file1, target_mac1)
    new_sig_i7s = build_WifiSig(file2, target_mac2)
    new_sig_mac = build_WifiSig(file3, target_mac3)
    new_sig_gh = build_WifiSig(file4, target_mac4)
    new_sig_i7 = build_WifiSig(file5, target_mac5)
    new_sig_i6 = build_WifiSig(file6, target_mac6)
    new_sig_i7s2 = build_WifiSig(file7, target_mac7)
    """print(ham_distance(new_sig_i7s, new_sig_i7s2))
    print(ham_distance(new_sig_i7s, new_sig_i6))
    print(ham_distance(new_sig_i7s, new_sig_i7))
    print(ham_distance(new_sig_i7s2, new_sig_i7))
    print(ham_distance(new_sig_i7s2, new_sig_i6))
    new_sig_i7s.display()
    new_sig_i7s2.display()"""
    sdc.clear_sig_database(db_file)
    sdc.save_new_sig(db_file, new_sig_huawei, device_name="huawei", device_type=0)
    sdc.save_new_sig(db_file, new_sig_i7s, device_name="i7s", device_type=0)
    sdc.save_new_sig(db_file, new_sig_mac, device_name="mac", device_type=1)
    sdc.save_new_sig(db_file, new_sig_gh, device_name="googlehome", device_type=2)
    sdc.save_new_sig(db_file, new_sig_i7, device_name="i7", device_type=0)
    sdc.save_new_sig(db_file, new_sig_i6, device_name="i6", device_type=0)

    (ret_dev_name, ret_dev_type) = ham_dist_judgement(db_file, new_sig_i7s2)
    print(ret_dev_name, ret_dev_type)