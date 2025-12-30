import os
import re
import csv

def extract_rule_data(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
        text = content.decode('utf-8', errors='ignore')
    
    # Extract all readable strings (4+ printable characters)
    strings = re.findall(r'[\x20-\x7E]{4,}', text)
    full_text = '|||'.join(strings)  # Join with delimiter for easier parsing
    
    # Try to extract specific fields
    rule_data = {
        'Filename': os.path.basename(file_path).replace('.rule', ''),
        'Rule Name': '',
        'Description': '',
        'Category': '',
        'OS Type': '',
        'Risk Level': '',
        'Status': '',
        'Did What (Raw)': '',
        'All Strings': ''
    }
    
    # Look for common patterns
    for i, s in enumerate(strings):
        # Rule name is often the filename without extension
        if 'Connecting unlisted' in s or len(s) > 20:
            pass  # We'll use filename as rule name fallback
        
        # Description often contains "alert" or "triggered"
        if 'triggered' in s.lower() or 'alert is' in s.lower():
            rule_data['Description'] = s
        
        # Category
        if s in ['DATA EXFILTRATION', 'COMPLIANCE', 'SUSPICIOUS ACTIVITY', 'FILE ACTIVITY', 
                 'PRIVILEGED USERS', 'SYSTEM TAMPERING', 'DATA THEFT']:
            rule_data['Category'] = s
        
        # OS Type
        if s in ['Windows', 'Mac', 'Linux', 'All']:
            rule_data['OS Type'] = s
            
        # Risk/Severity
        if s in ['Low', 'Medium', 'High', 'Critical']:
            rule_data['Risk Level'] = s
    
    # Use filename as Rule Name (usually matches)
    rule_data['Rule Name'] = os.path.basename(file_path).replace('.rule', '')
    
    # Dump all readable strings for manual review of "Did What?"
    rule_data['All Strings'] = ' | '.join(strings)
    
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
folder_path = r"C:\path\to\Data_Exfil"  # <-- Change this to your folder path
output_csv = r"C:\path\to\Data_Exfil_Rules.csv"  # <-- Change this to where you want the output

process_folder(folder_path, output_csv)
