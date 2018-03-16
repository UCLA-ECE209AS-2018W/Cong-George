import os
import time

def monitor_mode_setup(mon_card):
    monitor_card = mon_card

    os.system('airmon-ng check kill')
    print('wait for network setup...')
    time.sleep(5)

    os.system('ifconfig ' + monitor_card + ' down')
    #os.system('iwconfig ' + monitor_card + ' mode Monitor')
    os.system('airmon-ng start ' + monitor_card)
    os.system('ifconfig ' + monitor_card + ' up')
    os.system('ifconfig')
