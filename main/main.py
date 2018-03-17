from all_functions import *
from all_objects import *


# This is the main file of this project
if __name__ == "__main__":
    Ap_mac = '08:95:2a:6e:18:b8'
    general_card = 'wlan1'
    monitor_card = 'wlan1mon'

    # monitor_mode_setup(general_card)

    # the list to hold current active device
    new_sig_stats = sig_stats()

    # enter active phase
    active_phase(Ap_mac, monitor_card, new_sig_stats)
    passive_phase(Ap_mac, new_sig_stats, passive_dur='60', period=4, update_fre=3)
