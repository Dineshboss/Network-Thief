#! /usr/bin/env python
import scapy.all as scapy
import optparse

def argument():
    parser=optparse.OptionParser()
    parser.add_option("-r",dest="range", help="Range for scanning the network")
    (options,arguments)=parser.parse_args()
    return(options)

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast=broadcast/arp_request
    answered=scapy.srp(arp_request_broadcast,timeout=1, verbose=False)[0]
    arp_list=[]
    for element in answered:
        arp_dict={"iP":element[1].psrc, "mac":element[1].hwsrc}
        arp_list.append(arp_dict)
    return(arp_list)

def client(scan_result_final):
    print("IP" + "\t\t\t\t" + "Mac" + "\n" + "----------------------------------")
    for result_arp in scan_result_final:
             print(result_arp["iP"] + "\t\t" +result_arp["mac"])

options=argument()
scan_result=scan(options.range)
client(scan_result)




