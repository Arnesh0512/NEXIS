import os, re, sys

base_dir = os.path.abspath('services/ledger-go/subsystems')
subsystems = ['vault', 'auth', 'api', 'gateway', 'db', 'fraud', 'billing', 'compliance', 'notifications', 'orchestrator']

total_files = 0
total_functions = 0
modules_used = set()
deviations = []

target15 = [
    'golang.org/x/crypto/bcrypt',
    'github.com/cloudflare/circl',
    'github.com/golang-jwt/jwt',
    'golang.org/x/crypto/ssh',
    'crypto/cipher',
    'net/http',
    'github.com/go-resty/resty',
    'github.com/gin-gonic/gin',
    'go.mongodb.org/mongo-driver/mongo',
    'github.com/go-sql-driver/mysql',
    'github.com/lib/pq',
    'github.com/redis/go-redis',
    'github.com/sashabaranov/go-openai',
    'cloud.google.com/go/storage',
    'github.com/PuerkitoBio/goquery'
]

print("=== VERIFYING 50 GO SUBSYSTEM FILES ===")

fn_pattern = re.compile(r'func\s+(?:\([^)]*\)\s*)?([a-zA-Z0-9_]+)\s*\(')

for sub in subsystems:
    sub_dir = os.path.join(base_dir, sub)
    if not os.path.exists(sub_dir):
        print(f"Missing directory: {sub_dir}")
        continue
    files = [f for f in os.listdir(sub_dir) if f.endswith('.go')]
    print(f"\nSubsystem: {sub.upper()} ({len(files)} files)")
    total_files += len(files)

    for f in sorted(files):
        f_path = os.path.join(sub_dir, f)
        with open(f_path, 'r', encoding='utf-8') as fh:
            content = fh.read()
        
        matches = [m for m in fn_pattern.findall(content) if any(m.startswith(p) for p in ['abcd_', 'efgh_', 'ijkl_', 'mnop_'])]
        total_functions += len(matches)
        if len(matches) < 5 or len(matches) > 6:
            deviations.append((f, len(matches)))

        for m in target15:
            if m in content:
                modules_used.add(m)

        print(f"  - {f:<32} | {len(matches)} functions")

print("\n===============================================================")
print(f"Total Go Subsystem Files: {total_files} / 50")
print(f"Total Functions: {total_functions} (target ~250-300)")
print(f"Target Modules Encountered: {len(modules_used)} / {len(target15)}")
for m in sorted(target15):
    status = "PRESENT" if m in modules_used else "MISSING"
    print(f"  [{status}] {m}")

if deviations:
    print(f"\nWARNING: Files outside 5-6 functions range: {deviations}")
else:
    print("\nSUCCESS: All files have exactly 5 or 6 functions!")

if total_files == 50 and len(modules_used) >= 15 and not deviations:
    print("\n>>> ALL GO SUBSYSTEM CHECKS PASSED PERFECTLY! <<<")
else:
    print(f"\nStatus: Files={total_files}/50, Modules={len(modules_used)}/15")
