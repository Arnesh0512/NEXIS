import os, re, sys

base_dir = os.path.abspath('services/auth-kotlin/src/main/kotlin/com/nexis/identity')
subsystems = ['vault', 'token', 'api', 'gateway', 'db', 'fraud', 'billing', 'compliance', 'notifications', 'orchestrator']

total_files = 0
total_functions = 0
modules_used = set()
deviations = []

target15 = [
    'org.bouncycastle',
    'com.google.crypto.tink',
    'org.apache.commons.crypto',
    'io.jsonwebtoken',
    'jbcrypt',
    'io.ktor.client',
    'io.ktor.server',
    'io.ktor.network.tls',
    'okhttp3',
    'mongodb',
    'mysql',
    'postgresql',
    'redis.clients.jedis',
    'openai',
    'google.cloud.storage',
    'jsoup'
]

print("=== VERIFYING 50 KOTLIN SUBSYSTEM FILES ===")

fn_pattern = re.compile(r'fun\s+([a-zA-Z0-9_]+)\s*\(')

for sub in subsystems:
    sub_dir = os.path.join(base_dir, sub)
    if not os.path.exists(sub_dir):
        print(f"Missing directory: {sub_dir}")
        continue
    files = [f for f in os.listdir(sub_dir) if f.endswith('.kt')]
    print(f"\nSubsystem: {sub.upper()} ({len(files)} files)")
    total_files += len(files)

    for f in sorted(files):
        f_path = os.path.join(sub_dir, f)
        with open(f_path, 'r', encoding='utf-8') as fh:
            content = fh.read()
        
        matches = [m for m in fn_pattern.findall(content) if any(m.startswith(p) for p in ['abcd', 'efgh', 'ijkl', 'mnop'])]
        total_functions += len(matches)
        if len(matches) < 5 or len(matches) > 6:
            deviations.append((f, len(matches)))

        for m in target15:
            if m in content:
                modules_used.add(m)

        print(f"  - {f:<32} | {len(matches)} functions")

print("\n===============================================================")
print(f"Total Kotlin Subsystem Files: {total_files} / 50")
print(f"Total Structured Functions: {total_functions}")
print(f"Function Count Deviations (<5 or >6): {len(deviations)}")
if deviations:
    for d in deviations:
        print(f"  Deviation in {d[0]}: {d[1]}")

found = [m for m in target15 if m in modules_used]
missing = [m for m in target15 if m not in modules_used]
print(f"\n--- 15 TARGET MODULES AUDIT ---")
print(f"Target Modules Found ({len(found)}/{len(target15)}): {', '.join(found)}")
if missing:
    print(f"Missing Target Modules: {', '.join(missing)}")
    sys.exit(1)
else:
    print("ALL 15 TARGET MODULES FOUND IN IMPORTS!")
print("===============================================================")
