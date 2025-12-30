import os
import re
import csv

def extract_rule_data(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
        text = content.decode('utf-8', errors='ignore')
    
    strings = re.findall(r'[\x20-\x7E]{4,}', text)
    
    # EXPANDED junk patterns
    junk_patterns = [
        'ObserveIT', 'BusinessEntities', 'ActivityAlerts', 'BackingField',
        'System.', 'Microsoft.', 'mscorlib', 'Version=', 'Culture=', 
        'PublicKeyToken', 'xmlns', 'ArrayOf', 'schemas.datacontract',
        'schemas.microsoft', 'http://', 'https://', '.dll', 'Assembly',
        'RuleConditions', 'ActionConfiguration', 'AlertRule', 'Binary',
        'SerializationInfo', 'Exported', 'InAppElement', 'Config',
        '_Major', '_Minor', '_Build', '_Revision', '_items', '_size', '_version',
        'RuleCategory', 'RuleLogicOperators', 'RuleCondition', 'RuleUserList',
        'PreventionAlerts', 'BaseAction', 'eAssignMode', 'RuleHashItemFlags',
        'k_', '<', '>', 'Lry\'', 'Q@r', 'flario', 'DIRXXR', 'eD?d',
        'ExportVersion', 'TableName', 'IsDeleted', 'IsDeployed', 'IsSystem',
        'IsSpecial', 'IsDefaultAssigned', 'RulesCount', 'ListId', 'ListName',
        'LastUpdateTime', 'Property', 'Operator', 'OperatorStr', 'ObjectId',
        'ConditionOperators', 'Parent', 'OrderId', 'Adminb', 'value__',
        'TAQ7510'  # your username showing up
    ]
    
    categories = ['DATA EXFILTRATION', 'COMPLIANCE', 'SUSPICIOUS ACTIVITY', 
                  'FILE ACTIVITY', 'PRIVILEGED USERS', 'SYSTEM TAMPERING']
    os_types = ['Windows', 'Mac', 'Linux', 'Windows/Mac', 'All']
    risk_levels = ['Low', 'Medium', 'High', 'Critical', 'Info']
    
    rule_data = {
        'Rule Name': os.path.basename(file_path).replace('.rule', ''),
        'Description': '',
        'Category': '',
        'OS Type': '',
        'Risk Level': '',
        'Did What Strings': ''
    }
    
    leftover_strings = []
    
    for s in strings:
        s = s.strip()
        
        # Skip junk
        if any(junk in s for junk in junk_patterns):
            continue
        if len(s) < 4:
            continue
        # Skip if it's mostly special characters
        if sum(c.isalnum() or c.isspace() for c in s) < len(s) * 0.5:
            continue
            
        if ('triggered' in s.lower() or 'alert will be' in s.lower()) and len(s) > 50:
            rule_data['Description'] = s
            continue
        if s.upper() in [c.upper() for c in categories]:
            rule_data['Category'] = s
            continue
        if s in os_types:
            rule_data['OS Type'] = s
            continue
        if s in risk_levels:
            rule_data['Risk Level'] = s
            continue
        if s == rule_data['Rule Name']:
            continue
            
        leftover_strings.append(s)
    
    seen = set()
    unique_leftovers = []
    for s in leftover_strings:
        if s not in seen:
            seen.add(s)
            unique_leftovers.append(s)
    
    rule_data['Did What Strings'] = ' | '.join(unique_leftovers)
    
    return rule_data

def process_folder(folder_path, output_csv):
    all_rules = []
    for filename in os.listdir(folder_path):
        if filename.endswith('.rule'):
            file_path = os.path.join(folder_path, filename)
            print(f"Processing: {filename}")
            rule_data = extract_rule_data(file_path)
            all_rules.append(rule_data)
    
    if all_rules:
        with open(output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=all_rules[0].keys())
            writer.writeheader()
            writer.writerows(all_rules)
        print(f"\nDone! Wrote {len(all_rules)} rules to {output_csv}")

folder_path = r"C:\Users\TAQ7510\Downloads\Data_Exfil"
output_csv = r"C:\Users\TAQ7510\Downloads\Data_Exfil\Data_Exfil_Rules.csv"
process_folder(folder_path, output_csv)
