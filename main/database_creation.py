from all_functions import *

if __name__ == "__main__":
  db_file = "sig_database.p"
  pcap_dir_path = ""
  
  # create database and save it in "db_file"
  # create_database(db_file, pcap_dir_path)

  sig_file = "mac.pcap"
  target_mac = "c4:b3:01:c0:d7:55"
  device_name = "macpro"
  device_type = 1  # 0: phone, 1: laptop, 2: IotDevice, 3: other
  database_file = db_file

  #new_sig = build_WifiSig(sig_file, target_mac)
  #save_new_sig(database_file, new_sig, device_name, device_type)
  display_database(database_file)
