import os
import re
import csv

def extract_rule_data(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
        text = content.decode('utf-8', errors='ignore')
    
    # Get all readable strings
    strings = re.findall(r'[\x20-\x7E]{3,}', text)
    
    # Known "Did What" condition types from ObserveIT documentation
    did_what_conditions = [
        # Main conditions
        'Brought in a File', 'Copied Text', 'Detect Connected USB', 'Email',
        'Sent email', 'Exfiltrated File', 'Exfiltrated file', 'Executed SQL Command',
        'Logged In', 'Pasted', 'Ran Application', 'Used Keyboard', 'Visited URL',
        
        # Sub-options / Fields
        'By downloading from website', 'By saving attachment', 'By taking a file from cloud',
        'To website', 'To cloud storage', 'To USB device', 'By attaching it to an email',
        'By sending it via email',
        
        # Field names
        'Application name', 'Application full path', 'Process name', 'Window title',
        'Permission level', 'Typed text', 'Pressed special', 'combination keys',
        'Site', 'URL prefix', 'Any part of URL', 'Website category', 'Website name',
        'Website URL', 'Website window title',
        'Text content', 'Text Content', 'Pasted text', 'Pasted (text)',
        'Original file name', 'Original filename', 'Exfiltrated filename', 
        'Exfiltrated file path', 'File size', 'MIP Label',
        'Destination path', 'Destination', 'Vendor name',
        'USB model', 'USB vendor', 'USB label', 'USB S/N', 'USB ID',
        'Sender address', 'Email subject', 'Attachments', 'Number of recipients',
        'BCC recipients', 'At least one recipient', 'All recipients',
        'Copied Text', 'Used keyboard', 'Keylogging',
        
        # Operators
        'contains', 'does not contain', 'is', 'is not', 'starts with', 'ends with',
        'matches regex', 'is empty', 'is not empty', 'greater than', 'less than',
        'contain', 'Text contains'
    ]
    
    # Junk to filter
    junk_patterns = [
        'ObserveIT.', 'System.', 'Microsoft.', 'mscorlib', 
        'xmlns', 'http://', 'https://', 'schemas.',
        'BackingField', 'BusinessEntities', 'ActivityAlerts', 
        'ArrayOf', 'schemas.datacontract', 'Version=', 'Culture=',
        'PublicKeyToken', 'Assembly', '_items', '_size', '_version'
    ]
    
    categories = ['DATA EXFILTRATION', 'COMPLIANCE', 'SUSPICIOUS ACTIVITY', 
                  'FILE ACTIVITY', 'PRIVILEGED USERS', 'SYSTEM TAMPERING',
                  'DATA THEFT', 'SECURITY', 'THREAT DETECTION', 'FLIGHT RISK',
                  'BROWSING ACTIVITY', 'FRAUD', 'INAPPROPRIATE BEHAVIOR']
    os_types = ['Windows', 'Mac', 'Linux', 'Windows/Mac', 'All']
    risk_levels = ['Low', 'Medium', 'High', 'Critical', 'Info']
    
    rule_name = os.path.basename(file_path).replace('.rule', '')
    
    rule_data = {
        'Rule Name': rule_name,
        'Description': '',
        'Category': '',
        'OS Type': '',
        'Risk Level': '',
        'Did What Conditions': '',
        'Did What Fields': '',
        'Did What Values': ''
    }
    
    found_conditions = []
    found_fields = []
    found_values = []
    
    for s in strings:
        s = s.strip()
        if len(s) < 3:
            continue
        
        # Skip junk
        if any(j in s for j in junk_patterns):
            continue
        
        # Check if it's a known Did What condition/field
        is_known = False
        for condition in did_what_conditions:
            if condition.lower() in s.lower() or s.lower() in condition.lower():
                if len(s) > 2:
                    found_conditions.append(s)
                    is_known = True
                break
        
        # Extract known fields
        if ('triggered' in s.lower() or 'alert will be' in s.lower() or 
            'alert is triggered' in s.lower()) and len(s) > 30:
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
        
        if s == rule_name:
            continue
        
        # If not a known condition but looks like a value (starts with TD-, or is a list name)
        if s.startswith('TD -') or s.startswith('TD-'):
            found_values.append(s)
            continue
        
        # If not known and not junk, might be a value
        if not is_known and len(s) > 3:
            alnum_ratio = sum(c.isalnum() or c.isspace() for c in s) / len(s)
            if alnum_ratio > 0.7:
                found_values.append(s)
    
    # Dedupe and join
    rule_data['Did What Conditions'] = ' | '.join(sorted(set(found_conditions)))
    rule_data['Did What Values'] = ' | '.join(sorted(set(found_values)))
    
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

# === RUN IT ===
folder_path = r"C:\Users\TAQ7510\Downloads\ALL_Rules"
output_csv = r"C:\Users\TAQ7510\Downloads\ALL_Rules\All_Rules_Export.csv"
process_folder(folder_path, output_csv)
