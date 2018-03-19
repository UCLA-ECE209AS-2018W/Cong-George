from all_functions import *
from all_objects import *


# This is the main file of this project
if __name__ == "__main__":
    Ap_mac = '08:95:2a:6e:18:b8'
    general_card = 'wlan1'
    monitor_card = 'wlan1mon'

    # setup the monitor card
    # monitor_mode_setup(general_card)

    # scan nearby ap and return the ap_mac with the strongest SNR
    # Ap_mac = ap_scanning(monitor_card, duration='120')

    # the list to hold current active device
    new_sig_stats = sig_stats()

    # enter active phase
    active_phase(Ap_mac, monitor_card, new_sig_stats)

    # total time running: (passive_dur/60 * update_fre * period) mins
    passive_phase(Ap_mac, new_sig_stats, passive_dur='300', period=48, update_fre=6)
