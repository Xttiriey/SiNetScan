from prettytable import PrettyTable
import scapy.all as scapy
import argparse as ap
import re

pt = PrettyTable()

def get_arguments():
    parser = ap.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request 
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    all_list = []
    for element in answered_list: 
        user_list = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        all_list.append(user_list)

    return all_list

def manufacturer(macAdd):
    a = macAdd["mac"][0:8].replace(":", "-").upper()
    device = ""
    with open('MacList.txt') as f:
        mac_lines = f.readlines()
    for i in range(len(mac_lines)):
        if a in mac_lines[i]:
            result = [mac_lines[i]]
            res = result[0].replace("\n", "")
            device = res[res.find("|")+1:]
    return device

def print_result(results_list):
    pt.field_names = ["IP Address", "MAC Address", "Device manufacturer"]
    for client in results_list:
        pt.add_row([client["ip"], client["mac"], manufacturer(client)])
    print(pt)
  
options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
