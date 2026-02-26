import os
import re
import csv
import glob
import sys


def extract_strings(data, min_len=5):
    """Pull printable ASCII strings out of binary data."""
    strings = []
    current = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                strings.append(''.join(current))
            current = []
    if len(current) >= min_len:
        strings.append(''.join(current))
    return strings


def is_framework_noise(s):
    """Filter out .NET serialization metadata strings."""
    patterns = [
        r'(ObserveIT|System)\.\w+\.\w+',    # namespace paths
        r'k__BackingField',
        r'PublicKeyToken=',
        r'Culture=neutral',
        r'^Version=\d',
        r'mscorlib',
        r'^bet\.tis',
        r'Generic\.List',
        r'Nullable`',
        r'^\w+\.\w+\.\w+\.\w+',             # deep dotted namespaces
    ]
    for p in patterns:
        if re.search(p, s):
            return True
    if s.strip() in ('value__', 'True', 'False'):
        return True
    return False


def parse_rule_file(filepath):
    with open(filepath, 'rb') as f:
        raw = f.read()

    strings = extract_strings(raw, min_len=5)

    # ── DESCRIPTION ──────────────────────────────────────
    description = ""
    for s in strings:
        if "alert is triggered" in s.lower():
            idx = s.lower().find("an alert")
            if idx < 0:
                idx = s.lower().find("alert")
            if idx > 0:
                s = s[idx:]
            description = s.strip()
            break

    # Fallback: regex on decoded full file
    if not description:
        text = raw.decode('utf-8', errors='replace')
        m = re.search(r'(An alert is triggered.{10,300})', text)
        if m:
            desc = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', m.group(1))
            description = ' '.join(desc.split()).strip()

    # ── RULE NAME ────────────────────────────────────────
    # Get candidate strings (not framework noise, not the description)
    candidates = []
    for s in strings:
        s = s.strip()
        if (not is_framework_noise(s)
                and s != description
                and len(s) >= 8
                and ' ' in s
                and not any(c in s for c in '={}();\\[]<>$@#')):
            candidates.append(s)

    # Rule name is typically the FIRST clean human-readable phrase
    rule_name = ""
    for s in candidates:
        if len(s) <= 120:
            rule_name = s
            break

    # Fallback to filename
    if not rule_name:
        rule_name = os.path.splitext(os.path.basename(filepath))[0]

    return rule_name, description


def main():
    if len(sys.argv) > 1:
        folder = sys.argv[1]
    else:
        folder = input("Path to folder with .rule files: ").strip().strip('"')

    files = sorted(glob.glob(os.path.join(folder, "*.rule")))
    if not files:
        print(f"No .rule files found in: {folder}")
        sys.exit(1)

    print(f"Found {len(files)} .rule files\n")

    out_path = os.path.join(folder, "parsed_rules.csv")
    
    ok_count = 0
    warn_count = 0

    with open(out_path, 'w', newline='', encoding='utf-8') as csvf:
        writer = csv.writer(csvf)
        writer.writerow(["Rule Name", "Description", "Source File"])

        for fpath in files:
            name, desc = parse_rule_file(fpath)
            writer.writerow([name, desc, os.path.basename(fpath)])

            if name and desc:
                flag = "OK"
                ok_count += 1
            else:
                flag = "??"
                warn_count += 1

            print(f"[{flag}] {os.path.basename(fpath)}")
            print(f"      Name: {name[:90]}")
            print(f"      Desc: {desc[:90]}{'...' if len(desc) > 90 else ''}")
            print()

    print("=" * 60)
    print(f"Saved to:  {out_path}")
    print(f"Parsed OK: {ok_count}")
    print(f"Warnings:  {warn_count}")
    print(f"Total:     {len(files)}")


if __name__ == "__main__":
    main()
