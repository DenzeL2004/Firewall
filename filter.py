import argparse
import re 

class RulesList:
    def __init__(self, type : str):
        self.type = type == "white"
        self.rules =  list()
    
    def update(self, rule : dict) -> None:
        self.rules.append(rule)
    
    def match(self, packet) -> bool:
        pass

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("rules", type=str, help='Path to the file name with rules')
    parser.add_argument('ieth', type=str, help='Input interface')
    parser.add_argument('oeth', type=str, help='Output interface')
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
            if (conditions[i] == 'inPort' or conditions[i] == 'outPort'):
                rule.update({conditions[i] : int(conditions[i + 1])})
                pass
            else:         
                rule.update({conditions[i] : conditions[i + 1]})
        
        rules_list.update(rule)        
    
    return rules_list

def main(args):
    rule_list = define_rules(args.rules)
    

if __name__ == "__main__":
    main(parse_args())