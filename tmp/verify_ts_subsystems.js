const fs = require('fs');
const path = require('path');

const baseDir = path.resolve('services/api-gateway-ts/src/gateway_app');
const subsystems = ['vault', 'auth', 'api', 'gateway', 'db', 'fraud', 'billing', 'compliance', 'notifications', 'orchestrator'];

let totalFiles = 0;
let totalFunctions = 0;
const modulesUsed = new Set();
const functionCountErrors = [];

console.log('=== VERIFYING 50 TS SUBSYSTEM FILES ===');

for (const sub of subsystems) {
  const subDir = path.join(baseDir, sub);
  if (!fs.existsSync(subDir)) {
    console.error('Missing directory:', subDir);
    continue;
  }
  const files = fs.readdirSync(subDir).filter(f => f.endsWith('.ts') && f !== 'index.ts');
  console.log('\nSubsystem: ' + sub.toUpperCase() + ' (' + files.length + ' files)');
  totalFiles += files.length;

  for (const file of files) {
    const filePath = path.join(subDir, file);
    const content = fs.readFileSync(filePath, 'utf8');

    // Find functions starting with abcd_, efgh_, ijkl_, mnop_
    const fnRegex = /(?:export\s+(?:async\s+)?function\s+)([a-z]{4}_[a-zA-Z0-9_]+)/g;
    const matches = new Set();
    let m;
    while ((m = fnRegex.exec(content)) !== null) {
      if (['abcd_', 'efgh_', 'ijkl_', 'mnop_'].some(p => m[1].startsWith(p))) {
        matches.add(m[1]);
      }
    }
    totalFunctions += matches.size;
    if (matches.size < 5 || matches.size > 6) {
      functionCountErrors.push({ file, count: matches.size });
    }

    // Find imports
    const importRegex = /from\s+['"]([^'"]+)['"]/g;
    let r;
    const fileModules = new Set();
    while ((r = importRegex.exec(content)) !== null) {
      const mod = r[1].startsWith('.') ? path.basename(r[1]) : (r[1].startsWith('@') ? r[1].split('/').slice(0, 2).join('/') : r[1].split('/')[0]);
      modulesUsed.add(mod);
      fileModules.add(mod);
    }

    console.log('  - ' + file.padEnd(32) + ' | ' + matches.size + ' functions | imports: ' + Array.from(fileModules).slice(0, 3).join(', '));
  }
}

console.log('\n===============================================================');
console.log('Total TS Subsystem Files: ' + totalFiles + ' / 50');
console.log('Total Structured Functions: ' + totalFunctions);
console.log('Function Count Deviations (<5 or >6): ' + functionCountErrors.length);
if (functionCountErrors.length > 0) {
  functionCountErrors.forEach(e => console.error('  Function deviation in ' + e.file + ': ' + e.count));
}

const target15 = [
  'crypto-js', 'jsonwebtoken', 'jose', 'bcrypt', 'node-forge', 'ssh2',
  'axios', 'got', 'express', 'mongodb', 'mysql2',
  'pg', 'ioredis', 'openai', '@google-cloud/storage', 'cheerio'
];

console.log('\n--- 15 TARGET MODULES AUDIT ---');
const found = target15.filter(m => modulesUsed.has(m));
const missing = target15.filter(m => !modulesUsed.has(m));
console.log('Target Modules Found (' + found.length + '/' + target15.length + '): ' + found.join(', '));
if (missing.length > 0) {
  console.log('Missing Target Modules: ' + missing.join(', '));
  process.exit(1);
} else {
  console.log('ALL 15 TARGET MODULES FOUND IN IMPORTS!');
}
console.log('===============================================================');
