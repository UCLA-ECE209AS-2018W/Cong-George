import os
import operator
import csv


# find the AP with the strongest SNR and set the monitor channel to that AP
def ap_scanning(mon_card='wlan1mon', duration='10', file='ap_info'):
    monitor_card = mon_card
    scan_s = duration
    file_name = file
    chosen_bssid = ''
    file_path = os.system('pwd')
    channel = ''
    SSID = ''

    # save 5-second scanning result to a csv file
    print('scan for nearby AP...')
    os.system('rm ' + file_name + '*')
    os.system('timeout ' + scan_s + ' airodump-ng -w ' + file_name +
                                    ' --output-format csv -I 5 --ignore-negative-one '
                                    + monitor_card)

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

