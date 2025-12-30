import os
import re
import csv

def extract_rule_data(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
        text = content.decode('utf-8', errors='ignore')
    
    # Extract all readable strings (4+ printable characters)
    strings = re.findall(r'[\x20-\x7E]{4,}', text)
    
    # Known values to filter OUT (these are field names, common .NET stuff, etc.)
    junk_patterns = [
        'System.', 'Microsoft.', 'mscorlib', 'Version=', 'Culture=', 
        'PublicKeyToken', 'xmlns', 'ArrayOf', 'schemas.datacontract',
        'schemas.microsoft', 'http://', 'https://', '.dll', 'Assembly',
        'RuleConditions', 'ActionConfiguration', 'AlertRule', 'Binary',
        'SerializationInfo', 'Type', 'Value', 'Member', 'ObjectManager',
        'i4', 'i8', 'a]', 'b]', 'c]'  # common serialization fragments
    ]
    
    # Known categories - we'll extract these
    categories = ['DATA EXFILTRATION', 'COMPLIANCE', 'SUSPICIOUS ACTIVITY', 
                  'FILE ACTIVITY', 'PRIVILEGED USERS', 'SYSTEM TAMPERING', 
                  'DATA THEFT', 'SECURITY']
    
    # Known OS types
    os_types = ['Windows', 'Mac', 'Linux', 'Windows/Mac', 'All']
    
    # Known risk levels
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
        if len(s) < 5:
            continue
        
        # Check for Description (usually contains "alert" and "triggered")
        if ('triggered' in s.lower() or 'alert will be' in s.lower() or 'alert is' in s.lower()) and len(s) > 50:
            rule_data['Description'] = s
            continue
            
        # Check for Category
        if s.upper() in [c.upper() for c in categories]:
            rule_data['Category'] = s
            continue
            
        # Check for OS Type
        if s in os_types:
            rule_data['OS Type'] = s
            continue
            
        # Check for Risk Level
        if s in risk_levels:
            rule_data['Risk Level'] = s
            continue
        
        # Skip the rule name itself
        if s == rule_data['Rule Name']:
            continue
            
        # Everything else goes to leftovers (potential Did What? content)
        leftover_strings.append(s)
    
    # Remove duplicates while preserving order
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
    
    # Write to CSV
    if all_rules:
        with open(output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=all_rules[0].keys())
            writer.writeheader()
            writer.writerows(all_rules)
        print(f"\nDone! Wrote {len(all_rules)} rules to {output_csv}")

# === RUN THIS ===
folder_path = r"C:\Users\TAQ7510\Downloads\Data_Exfil"
output_csv = r"C:\Users\TAQ7510\Downloads\Data_Exfil\Data_Exfil_Rules.csv"

process_folder(folder_path, output_csv)
