import argparse
import re 
import os
import socket
from socket import AF_PACKET, AF_INET, SOCK_RAW, ETH_P_ALL

import dpkt

BUF_SZIE = 1024

FILTER_COND = {'prot', 'srcIP', 'dstIP', 'srcPort', 'dstPort'} 

class RulesList:
    def __init__(self, type : str):
        self.is_white = (type == "white")
        self.rules =  list()
    
    def update(self, rule : dict) -> None:
        self.rules.append(rule)
    
    def match(self, pkt, rule) -> bool:
        match = True
        for key in FILTER_COND:
            if (key in rule.keys()) and (key in pkt.keys()):
                match &= (rule[key] == pkt[key])
        
        return match
                

    def passed(self, pkt) -> bool:
        match = False
        for rule in self.rules:
            match = self.match(pkt, rule)
            if match: 
                break
        
        return (not self.is_white and not match) or (self.is_white and match)
        

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("rules", type=str, help='Path to the file name with rules')
    parser.add_argument('ifIn', type=str, help='Input interface')
    parser.add_argument('ifOut', type=str, help='Output interface')
    return parser.parse_args()

def define_rules(path : str) -> RulesList:
    with open(path, 'r') as file:
        content = file.read()
    
    if content.find("white") != -1: 
        rules_list = RulesList("white")
    elif content.find("black") != -1:
        rules_list = RulesList("black")
    else:
        raise Exception('Invalide type RuleList. Must be \'black\' or \'white\'.')

    begin = content.find('{', content.find("rules") + 1)
    while begin != -1:
        begin = content.find('{', begin + 1)
        if (begin == -1):
                break
            
        end = content.find('}', begin)
        if end == -1:
            raise Exception("No closed \'}\'.")
        
        conditions = list(filter(None, re.split(r'[\s:,]', content[begin + 1: end - 1])))

        rule = dict()
        for i in range(0, len(conditions), 2):
            if conditions[i] not in FILTER_COND:
                raise Exception(f"Undefine condition:{conditions[i]}.")
            
            if (conditions[i] == 'dstPort' or conditions[i] == 'srcPort'):
                rule.update({conditions[i] : socket.htons(int(conditions[i + 1]))})
            else:         
                rule.update({conditions[i] : conditions[i + 1]})
        
        rules_list.update(rule)        
    
    return rules_list

def create_socket(if_name : str) -> socket:
    sock = socket.socket(AF_PACKET, SOCK_RAW)
    sock.bind((if_name, ETH_P_ALL))
    return sock

def print_packet(pkt) -> None:
    for key, val in pkt.items():
        print(f"{key}: {val}")
    
        
def define_packet(eth : dpkt.ethernet.Ethernet) -> dict:
    ip = eth.data
    
    srcIP = str(socket.inet_ntop(AF_INET, ip.src))
    dstIP = str(socket.inet_ntop(AF_INET, ip.dst))
    
    if isinstance(ip.data, dpkt.tcp.TCP):
        pkt = {'prot'    : 'tcp', 
               'srcIP'   : srcIP, 
               'dstIP'   : dstIP,
               'srcPort' : socket.ntohs(ip.data.sport),
               'dstPort' : socket.ntohs(ip.data.dport)}
    
    if isinstance(ip.data, dpkt.udp.UDP):
        pkt = {'prot'    : 'udp', 
               'srcIP'   : srcIP, 
               'dstIP'   : dstIP,
               'srcPort' : socket.ntohs(ip.data.sport),
               'dstPort' : socket.ntohs(ip.data.dport)}
        
    if isinstance(ip.data, dpkt.icmp.ICMP):
        pkt = {'prot'    : 'icmp', 
               'srcIP'   : srcIP, 
               'dstIP'   : dstIP}
        
    return pkt

def myfilter(input : socket, output : socket, rules : RulesList) -> bool:
    data = input.recv(BUF_SZIE)
    
    eth = dpkt.ethernet.Ethernet(data)
    if not isinstance(eth.data, dpkt.ip.IP):
        print("Skip package");
    else:
        pkt = define_packet(eth)
        print_packet(pkt)
        
        if rules.passed(pkt):
            print("Pass packet.")
        else:
            print("Drop packet.")
            return False
        
    output.sendall(data)
    return True
        

def main(args):
    rules_list = define_rules(args.rules)
    
    input  = create_socket(args.ifIn)
    output = create_socket(args.ifOut)
    
    if os.fork():
        while(True):
            myfilter(input, output, rules_list)
    else:
        while(True):
            myfilter(output, input, rules_list)

if __name__ == "__main__":
    main(parse_args())