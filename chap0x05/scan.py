import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP,TCP,sr1,RandShort,send,ICMP,UDP,Raw

dst_ip = "192.168.56.107"

import argparse

def tcp_scan_1(dst_ip, dst_port, scan_way):
    src_port = RandShort()
    scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),verbose=0,timeout=2)
    if scan_resp == None:
        if scan_way == "T": 
            return "Closed"
        elif scan_way=="S":
            return "Filtered"
    elif (scan_resp.haslayer(ICMP)):
        if scan_way == "T":
            return "Closed"
        elif(int(scan_resp.getlayer(ICMP).type)==3 and int(scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Filtered"
    elif (scan_resp.haslayer(TCP)):
        if (scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
        if (scan_resp.getlayer(TCP).flags == 0x12):
            if scan_way=="T":
                send_rst = send(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),verbose=0)
            elif scan_way=="S":
                send_rst = send(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),verbose=0)
            return "Open"
    
    
def tcp_scan_2(dst_ip, dst_port, scan_way):
    if (scan_way == 'X'):
        flags = "FPU"
    elif (scan_way == 'N'):
        flags = ""
    elif (scan_way == 'F'):
        flags="F"
    scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=flags),verbose=0,timeout=2)
    if scan_resp == None:
        return "Open|Filtered"
    elif(scan_resp.haslayer(TCP)):
        if(scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    elif(scan_resp.haslayer(ICMP)):
        if(int(scan_resp.getlayer(ICMP).type)==3 and int(scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Filtered"
def udp_scan(dst_ip, dst_port):
    scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),verbose=0,timeout=1)
    if scan_resp == None: 
        # `retrans = []
        # for count in range(0,3):
        #     retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=5))
        # for item in retrans:
        #     if (str(type(item))!=""):
        #         udp_scan(dst_ip,dst_port,5)`
        return "Open | Filtered"
    elif (scan_resp.haslayer(UDP)):
        return "Open"
    elif (scan_resp.haslayer(ICMP)):
        if(int(scan_resp.getlayer(ICMP).type)==3 and int(scan_resp.getlayer(ICMP).code)==3):
            return "Closed" 
        elif(int(scan_resp.getlayer(ICMP).type)==3 and int(scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
            return "Filtered"

parser = argparse.ArgumentParser()
parser.add_argument("dst_ip", type = str,help = "destination_ip")
parser.add_argument("dst_port",type = int, help = "destination_port")

scan_choices=['S', 'U', 'N','X','T','F']
parser.add_argument("-s",'--scan',dest='s',
                    default='S',
                    choices=scan_choices)

args = parser.parse_args()
if args.dst_ip:
    dst_ip = args.dst_ip
if args.dst_port:
    dst_port = args.dst_port
my_scan_way = args.s
if my_scan_way not in scan_choices:
    print("error")
else:
    if my_scan_way in ['S' , 'T']:
        res=tcp_scan_1(dst_ip, dst_port, my_scan_way)
    elif my_scan_way in ['N' ,'X' ,'F']:
        res=tcp_scan_2(dst_ip, dst_port, my_scan_way)
    elif my_scan_way == 'U':
        res = udp_scan(dst_ip, dst_port)
    print(dst_ip+"'s port"+str(dst_port)+' is '+res)    
