import argparse
import re 
import enum
import socket
from socket import AF_PACKET, AF_INET, SOCK_RAW, ETH_P_ALL
from netfilterqueue import NetfilterQueue
import dpkt

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
                match &= rule[flag].match(pkt[flag]) is not None
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
    parser.add_argument('--queue-num', type=int, default=5)
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
                        rule.update({flag : re.compile(arg)})
                    
                    if flag in ['type', 'class', 'length']:
                        rule.update({flag : int(arg)})
                    
            rules_list.update(rule)              
            
    return rules_list
    

def create_socket(if_name : str) -> socket:
    sock = socket.socket(AF_PACKET, SOCK_RAW)
    sock.bind((if_name, ETH_P_ALL))
    return sock

def print_packet(pkt) -> None:
    for key, val in pkt.items():
        print(f"{key}: {val}")
    
        
def check_is_dns(data) -> bool:
    eth = dpkt.ethernet.Ethernet(data)
    ip = eth.data
    udp = ip.data
    return isinstance(udp.data, dpkt.dns.DNS)
    
def get_dns_packet(data) -> dict:
    ip = dpkt.ethernet.Ethernet(data).data
    udp = ip.data
    dns = dpkt.dns.DNS(udp.data)
    
    pkt = dict({"prot" : "DNS"})
    if dns.qr == dpkt.dns.DNS_R:
        rr_data, off = dns.unpack_rr(data, 0)
        pkt.update({"QR"    : 1,
                    "name"  : rr_data.name,
                    "type"  : rr_data.type, 
                    "class" : rr_data.cls, 
                    "len"   : rr_data.rlaen, 
                    "data"  : rr_data.rdata})
        
    if dns.qr == dpkt.dns.DNS_Q:
        q_data, off = dns.unpack_q(data, 0)
        pkt.update({"QR"    : 0,
                    "name"  : q_data.name,
                    "type"  : q_data.type, 
                    "class" : q_data.cls})
        
    return pkt

def packet_handler(pkt, rules : RulesList):
    data = pkt.get_payload()
    
    if not check_is_dns(data):
        print("Skip package");
    else:
        pkt = get_dns_packet(data)
        print_packet(pkt)
        
        act_type = rules.passed(pkt)
        if act_type == Action.drop:
            print("Drop")
            return pkt.drop()
        else:
            print("Accept")        

    return pkt.accept()
        

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