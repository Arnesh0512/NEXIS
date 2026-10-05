import os, re, sys

base_dir = os.path.abspath('services/crypto-rs/src/subsystems')
subsystems = ['vault', 'auth', 'api', 'gateway', 'db', 'fraud', 'billing', 'compliance', 'notifications', 'orchestrator']

total_files = 0
total_functions = 0
modules_used = set()
deviations = []

target15 = [
    'ring',
    'aes_gcm',
    'pqcrypto',
    'jsonwebtoken',
    'bcrypt',
    'reqwest',
    'actix',
    'tokio',
    'mongodb',
    'mysql',
    'postgres',
    'redis',
    'openai',
    'google_cloud_storage',
    'scraper'
]

print("=== VERIFYING 50 RUST SUBSYSTEM FILES ===")

fn_pattern = re.compile(r'pub\s+fn\s+([a-zA-Z0-9_]+)\s*\(')

for sub in subsystems:
    sub_dir = os.path.join(base_dir, sub)
    if not os.path.exists(sub_dir):
        print(f"Missing directory: {sub_dir}")
        continue
    files = [f for f in os.listdir(sub_dir) if f.endswith('.rs') and f != 'mod.rs']
    print(f"\nSubsystem: {sub.upper()} ({len(files)} files)")
    total_files += len(files)

    for f in sorted(files):
        f_path = os.path.join(sub_dir, f)
        with open(f_path, 'r', encoding='utf-8', errors='ignore') as fh:
            content = fh.read()
        
        matches = [m for m in fn_pattern.findall(content) if any(m.startswith(p) for p in ['abcd_', 'efgh_', 'ijkl_', 'mnop_'])]
        total_functions += len(matches)
        if len(matches) < 5 or len(matches) > 6:
            deviations.append((f, len(matches)))

        content_lower = content.lower()
        for m in target15:
            if m.lower() in content_lower:
                modules_used.add(m)

        print(f"  - {f:<32} | {len(matches)} functions")

print("\n===============================================================")
print(f"Total Rust Subsystem Files: {total_files} / 50")
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
    print("\n>>> ALL RUST SUBSYSTEM CHECKS PASSED! <<<")
else:
    print(f"\nStatus: Files={total_files}/50, Modules={len(modules_used)}/{len(target15)}")
