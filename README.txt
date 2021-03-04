This Python program was written in KALI linux to simulate Man in the middle attack in a vulnerable network.

arpspoofer.py program spoofs the target machine and router by poisoning the ARP table. It keeps on spoofing
every two seconds since the ARP table gets updated automatically.

After the spoofing is done, pswrdsniffer.py program sniffs for packet transferred between the target machine
and the router and parses the unencrypted data.