#! usr/bin/env python
import argparse
import scapy.all as scapy
def argument():
    parser=argparse.ArgumentParser()
    parser.add_argument("-r",dest="range",help="IP range to scan the Network")
    options=parser.parse_args()
    if not options.range:
        parser.error("Please specify the ip range")
    return(options)
def get_packet(ip):
    scapy_packet = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet_final = broadcast / scapy_packet
    answered = scapy.srp(packet_final, timeout=1)[0]
    print("IP" + "\t\t" + " Mac-Address")
    return(answered)

def capture(ip):
   answered=get_packet(ip)
   ip_dict={}
   for answer in answered:
       ip_dict[answer[1].psrc]= answer[1].src
   for key in ip_dict.keys():
        print(key + "\t" + ip_dict[key])

options=argument()
capture(options.range)
