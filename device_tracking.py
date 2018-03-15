import subprocess
import os
import csv
import time


# return a list of devices connected to a AP
def device_tracking(ap_mac, channel, mon_card='wlan1mon', duration='60', file_name = 'dev_summary'):
    devices = []

    # save duration-second scanning result to a csv file
    os.system('rm ' + file_name + '*')
    subprocess.call('timeout ' + duration + ' airodump-ng -w ' + file_name +
                                    ' --output-format csv -I 5 --ignore-negative-one ' +
                                    ' -c ' + channel + ' --bssid ' + ap_mac + ' '
                                    + mon_card, shell=True)
    '''
    subprocess.call('timeout ' + duration + ' airodump-ng -w ' + file_name +
             ' --output-format csv -I 5 --ignore-negative-one ' +
             ' -c ' + channel + ' --bssid ' + ap_mac + ' '
             + mon_card, shell=True)
    
    subprocess.call(['timeout', duration, 'airodump-ng', '-w', file_name,
              '--output-format', 'csv', '-I', '5', '--ignore-negative-one',
              '-c', channel, '--bssid', ap_mac, mon_card], shell=True)'''

    reader = csv.reader(open(file_name + '-01.csv'))
    list_reader = list(reader)
    ap_data = list_reader[2][-6]

    for i, line in enumerate(list_reader):
        if i > 5 and len(line) > 0:
            devices.append(line[0])

    return devices