import argparse
import re 
import enum
import socket
from socket import AF_PACKET, AF_INET, SOCK_RAW, ETH_P_ALL
from netfilterqueue import NetfilterQueue
from scapy.all import *

BUF_SZIE = 1024
PROTOCOLS = ['DNS']
PROTOCOLS_FLAGS =   {'DNS' : {  0 : ['name', 'type', 'class'],
                                1 : ['name', 'type', 'class', 'len', 'data']
                             }

                    }

class Action(enum.Enum):
    drop = 0
    accept = 1
    default = 2

class RulesList:
    def __init__(self):
        self.rules =  list()
    
    def update(self, rule : dict) -> None:
        self.rules.append(rule)
    
    def match(self, pkt, rule) -> bool:
        match = True
        for flag in pkt.keys():
            if flag not in rule.keys():
                continue
            
            if flag in ['name', 'data']:
                match &=  pkt[flag].find(rule[flag]) != -1
            else:
                match &= pkt[flag] == rule[flag]
            
            if not match: 
                break
                
        if match:
            return rule['action']
        
        return Action.default
                
    def passed(self, pkt) -> bool:
        match = Action.default
        for rule in self.rules:
            match = self.match(pkt, rule)
            if match == Action.drop or match == Action.accept: 
                break
            
        return match
    
    def show_rules(self):
        for rule in self.rules:
            print(rule)
        

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("rules", type=str)
    parser.add_argument('--queue-num', type=int, default=1)
    return parser.parse_args()

def parse_cond(cond : str):
    args = cond.strip().split(sep='=')
    if len(args) != 2:
        raise ("Uncorrect arguments, format must be \'flag=arg\'.\n")

    return args[0], args[1]

def define_rules(path : str) -> RulesList:
    rules_list = RulesList()
    
    with open(path, 'r') as file:
        for line in file:
            if len(line) == 0:
                continue
            
            conds = line.strip().split()
            rule = dict()
            
            flag, type = parse_cond(conds[0])
            if flag != 'action':
                raise Exception('First argument must be \'action\'=num.\n')
            
            if type not in ['0', '1']:
                raise Exception('Action flag must be 0 or 1.')
            
            if type == '0':
                rule.update({'action' : Action.drop})
            else:
                rule.update({'action' : Action.accept})
            
            prot = conds[1]
            if prot not in PROTOCOLS:
                raise Exception(f'Undefind prot={prot}.\n')
            
            rule.update({'prot' : prot})
            
            if prot == 'DNS':
                if len(conds) < 2:
                    raise Exception(f'Under DNS protocols, the second argument must always be the request type.\n')
                
                flag, type = parse_cond(conds[2])
                if flag != 'QR':
                    raise Exception("Under DNS protocols, the second argument must always be the request type.\n")
                
                type = int(type)
                if type not in [0, 1]:
                    raise Exception("Uncorrect QR value. Must be 0 or 1.\n")
                rule.update({'QR' : int(type)})
                
                for i in range(3, len(conds)):
                    flag, arg = parse_cond(conds[i])
                    if flag not in PROTOCOLS_FLAGS['DNS'][type]:
                        raise Exception(f"Undefine flag({flag})")

                    if flag in ['name', 'data']:
                        rule.update({flag : arg})
                    
                    if flag in ['type', 'class', 'length']:
                        rule.update({flag : int(arg)})
            
            print(rule)
            rules_list.update(rule)              
            
    return rules_list
    

def create_socket(if_name : str) -> socket:
    sock = socket.socket(AF_PACKET, SOCK_RAW)
    sock.bind((if_name, ETH_P_ALL))
    return sock

def print_packet(pkt) -> None:
    for key, val in pkt.items():
        print(f"{key}: {val}")
    print("\n")
    
        
def check_is_dns(pkt) -> bool:
    return pkt.haslayer(DNS)
    
def get_dns_packet(pkt) -> dict:
    my_pkt = dict({"prot" : "DNS"})
    
    if pkt.haslayer(DNSRR):
        rr = pkt.getlayer(DNSRR)
        my_pkt.update({"QR"    : 1,
                        "name"  : rr.get_field('rrname').i2repr(rr, rr.rrname),
                        "type"  : rr.type, 
                        "class" : rr.rclass, 
                        "len"   : rr.rdlen, 
                        "data"  : rr.get_field('rdata').i2repr(rr, rr.rdata)})
    elif pkt.haslayer(DNSQR):
        qr = pkt.getlayer(DNSQR)
        my_pkt.update({ "QR"    : 0,
                        "name"  : qr.get_field('qname').i2repr(qr, qr.qname),
                        "type"  : qr.qtype,
                        "class" : qr.qclass})
        
    return my_pkt

def packet_handler(pkt, rules : RulesList):
    
    scp_pkt = IP(pkt.get_payload())
    
    if not check_is_dns(scp_pkt):
        print("Skip package\n")
    else:
        my_pkt = get_dns_packet(scp_pkt)
        print_packet(my_pkt)
        
        act_type = rules.passed(my_pkt)
        if act_type == Action.drop:
            print("Drop\n")
            pkt.drop()
            return
        else:
            print("Accept\n")        

    pkt.accept()
        

def main(args):
    rules_list = define_rules(args.rules)
    
    nfqueue = NetfilterQueue()
    wrapper = lambda pkt: packet_handler(pkt, rules_list)
    
    nfqueue.bind(int(args.queue_num), wrapper)
    sock = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
    
    try:
        nfqueue.run_socket(sock)
    except KeyboardInterrupt:
        pass

    sock.close()
    nfqueue.unbind()

if __name__ == "__main__":
    main(parse_args())