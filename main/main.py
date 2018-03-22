import getopt
from all_functions import *
from all_objects import *


def main():
    Ap_mac = '08:95:2a:6e:18:b8'
    general_card = 'wlan1'
    monitor_card = 'wlan1mon'
    passive_duration = '300'
    ap_scan_dur = '120'
    per = 48
    up_fre = 6

    # setup the monitor card
    monitor_mode_setup(general_card)

    # scan nearby ap and return the ap_mac with the strongest SNR
    if len(Ap_mac) == 0 or Ap_mac is None:
        Ap_mac = ap_scanning(monitor_card, duration=ap_scan_dur)

    # the list to hold current active device
    new_sig_stats = sig_stats()

    # enter active phase
    active_phase(Ap_mac, monitor_card, new_sig_stats)

    # total time running: (passive_dur/60 * update_fre * period) mins
    passive_phase(Ap_mac, new_sig_stats, passive_dur=passive_duration, period=per, update_fre=up_fre)


def main_script(argv):
    Ap_mac = '08:95:2a:6e:18:b8'
    general_card = 'wlan1'
    monitor_card = 'wlan1mon'
    passive_duration = '300'
    ap_scan_dur = '120'
    per = 48
    up_fre = 6

    try:
        opts, args = getopt.getopt(argv, "ha:g:m:p:s:t:", ["ap_mac=", "general_card=",
                                                           "monitor_card=", "passive_dur=",
                                                           "ap_scan_dur=","running_time="])
    except getopt.GetoptError:
        print("Wrong input arguments, please refer for airOccupant.py -h for more info")
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-h":
            print("\n\n\nairOccupant.py is an awesome script used to monitor target house occupancy"
                  "It will automatically identify all smart devices in the target network and tell "
                  "house occupancy info by monitoring presents of smart phones\n")
            print("Author: George Li, Colin Cong")
            print("UCLA ECE 209AS course project\n")
            print("Usage: airOccupat.py or airOccupat <option> <arguments>")
            print("airOccupant.py supported arguments:\n")
            print("-h display help info\n")
            print("-a, --ap_mac <AP mac address> use predefined Ap_mac address\n")
            print("-g --general_card <card name> use specified card\n")
            print("-m --monitor_card <monitor interface name> use specified monitor mode interface\n")
            print("-p --passive_dur <minutes> set report update frequency\n")
            print("-s --ap_scan_dur <second> set time take to scan for nearby AP\n")
            print("-t --running_time <hour> set total running hours\n")
            sys.exit()
        elif opt in ("-a", "--ap_mac"):
            Ap_mac = arg
        elif opt in ("-g", "--general_card"):
            general_card = arg
        elif opt in ("-m", "--monitor_card"):
            monitor_card = arg
        elif opt in ("-p", "--passive_dur"):
            passive_duration = int(int(arg)*60/up_fre)
        elif opt in ("-s", "--ap_scan_dur"):
            ap_scan_dur = arg
        elif opt in ("-t", "--running_time"):
            per = int(60/(up_fre*float(passive_duration)/60)*float(arg))

    print("Total running hours: {} hours\nUpdate frequency: every {} minute".format(per, up_fre*float(passive_duration)/60))

    # setup the monitor card
    monitor_mode_setup(general_card)

    # scan nearby ap and return the ap_mac with the strongest SNR
    if len(Ap_mac) == 0 or Ap_mac is None:
        Ap_mac = ap_scanning(monitor_card, duration=ap_scan_dur)

    # the list to hold current active device
    new_sig_stats = sig_stats()

    # enter active phase
    active_phase(Ap_mac, monitor_card, new_sig_stats)

    # total time running: (passive_dur/60 * update_fre * period) mins
    passive_phase(Ap_mac, new_sig_stats, passive_dur=passive_duration, period=per, update_fre=up_fre)


# This is the main file of this project
if __name__ == "__main__":
    #main_script(sys.argv[1:])
    main()