import os
import re
import csv

def extract_rule_data(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
        text = content.decode('utf-8', errors='ignore')
    
    strings = re.findall(r'[\x20-\x7E]{4,}', text)
    
    junk_starts = [
        'ObserveIT.', 'System.', 'Microsoft.', 'mscorlib', 
        'xmlns', 'http://', 'https://', 'schemas.',
        'k__BackingField', '<', '>'
    ]
    
    junk_contains = [
        'BackingField', 'BusinessEntities', 'ActivityAlerts', 
        'ArrayOf', 'schemas.datacontract'
    ]
    
    categories = ['DATA EXFILTRATION', 'COMPLIANCE', 'SUSPICIOUS ACTIVITY', 
                  'FILE ACTIVITY', 'PRIVILEGED USERS', 'SYSTEM TAMPERING',
                  'DATA THEFT', 'SECURITY', 'THREAT DETECTION']
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
        if len(s) < 4:
            continue
        if any(s.startswith(j) for j in junk_starts):
            continue
        if any(j in s for j in junk_contains):
            continue
        
        alnum_ratio = sum(c.isalnum() or c.isspace() for c in s) / len(s)
        if alnum_ratio < 0.6:
            continue
            
        if ('triggered' in s.lower() or 'alert will be' in s.lower()) and len(s) > 30:
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

# === ALL RULES ===
folder_path = r"C:\Users\TAQ7510\Downloads\ALL_Rules"
output_csv = r"C:\Users\TAQ7510\Downloads\ALL_Rules\All_Rules_Export.csv"
process_folder(folder_path, output_csv)
