import os
import time

monitor_card = 'wlan1'
general_card = 'wlan0'

os.system('airmon-ng check kill')
print('wait for network setup...')
time.sleep(5)

os.system('ifconfig ' + monitor_card + ' down')
#os.system('iwconfig ' + monitor_card + ' mode Monitor')
os.system('airmon-ng start ' + monitor_card)
os.system('ifconfig ' + monitor_card + ' up')
os.system('ifconfig')