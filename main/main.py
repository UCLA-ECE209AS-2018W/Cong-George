from all_functions import *
from all_objects import *


# This is the main file of this project
if __name__ == "__main__":
    ap_mac = '08:95:2a:6e:18:b8'
    monitor_card = 'wlan1mon'

    # the list to hold current active device
    new_sig_stats = sig_stats()

    # enter active phase
    active_phase(ap_mac, monitor_card, new_sig_stats)
    # passive_phase(ap_mac, "2", new_sig_stats, passive_dur='300', period=3, update_fre=4)
