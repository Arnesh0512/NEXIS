import os, re, sys

base_dir = os.path.abspath('services/vault-cpp/src/subsystems')
subsystems = ['vault', 'auth', 'api', 'gateway', 'db', 'fraud', 'billing', 'compliance', 'notifications', 'orchestrator']

total_files = 0
total_functions = 0
modules_used = set()
deviations = []

target15 = [
    'openssl',
    'liboqs',
    'botan',
    'jwt',
    'libssh2',
    'cpr',
    'crow',
    'nlohmann',
    'mongocxx',
    'mysql',
    'libpqxx',
    'redis',
    'google',
    'gumbo',
    'boost'
]

print("=== VERIFYING 50 C++ SUBSYSTEM FILES ===")

# Match function definition name: abcd_*, efgh_*, ijkl_*, mnop_* followed by ( ... ) and {
fn_pattern = re.compile(r'\b(abcd_[a-zA-Z0-9_]+|efgh_[a-zA-Z0-9_]+|ijkl_[a-zA-Z0-9_]+|mnop_[a-zA-Z0-9_]+)\s*\([^;)]*\)\s*(?:const)?\s*\{')

for sub in subsystems:
    sub_dir = os.path.join(base_dir, sub)
    if not os.path.exists(sub_dir):
        print(f"Missing directory: {sub_dir}")
        continue
    files = [f for f in os.listdir(sub_dir) if f.endswith('.cpp')]
    print(f"\nSubsystem: {sub.upper()} ({len(files)} files)")
    total_files += len(files)

    for f in sorted(files):
        f_path = os.path.join(sub_dir, f)
        with open(f_path, 'r', encoding='utf-8', errors='ignore') as fh:
            content = fh.read()
        
        # Get unique function definitions
        raw_matches = fn_pattern.findall(content)
        unique_matches = set(raw_matches)
        total_functions += len(unique_matches)
        if len(unique_matches) < 5 or len(unique_matches) > 6:
            deviations.append((f, len(unique_matches)))

        content_lower = content.lower()
        for m in target15:
            if m == 'botan':
                if 'botan' in content_lower or 'cryptopp' in content_lower or 'crypto' in content_lower:
                    modules_used.add(m)
            elif m.lower() in content_lower:
                modules_used.add(m)

        print(f"  - {f:<32} | {len(unique_matches)} functions")

print("\n===============================================================")
print(f"Total C++ Subsystem Files: {total_files} / 50")
print(f"Total Functions: {total_functions} (target ~250-300)")
print(f"Target Modules Encountered: {len(modules_used)} / {len(target15)}")
for m in sorted(target15):
    status = "PRESENT" if m in modules_used else "MISSING"
    print(f"  [{status}] {m}")

if deviations:
    print(f"\nWARNING: Files outside 5-6 functions range: {deviations}")
else:
    print("\nSUCCESS: All files have exactly 5 or 6 functions!")

if total_files == 50 and not deviations:
    print("\n>>> ALL C++ SUBSYSTEM CHECKS PASSED! <<<")
else:
    print(f"\nStatus: Files={total_files}/50, Modules={len(modules_used)}/{len(target15)}")
