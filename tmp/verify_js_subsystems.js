const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const baseDir = path.resolve('services/edge-router-js/src/router_app');
const subsystems = ['vault', 'auth', 'api', 'gateway', 'db', 'fraud', 'billing', 'compliance', 'notifications', 'orchestrator'];

let totalFiles = 0;
let totalFunctions = 0;
const modulesUsed = new Set();
const syntaxErrors = [];
const functionCountErrors = [];

console.log('=== VERIFYING 50 JS SUBSYSTEM FILES ===');

for (const sub of subsystems) {
  const subDir = path.join(baseDir, sub);
  if (!fs.existsSync(subDir)) {
    console.error('Missing directory:', subDir);
    continue;
  }
  const files = fs.readdirSync(subDir).filter(f => f.endsWith('.js') && f !== 'index.js');
  console.log('\nSubsystem: ' + sub.toUpperCase() + ' (' + files.length + ' files)');
  totalFiles += files.length;

  for (const file of files) {
    const filePath = path.join(subDir, file);
    
    // 1. Syntax check
    try {
      execSync('node --check "' + filePath + '"', { stdio: 'pipe' });
    } catch (err) {
      syntaxErrors.push({ file: filePath, error: err.message });
    }

    // 2. Read content and analyze functions & requires
    const content = fs.readFileSync(filePath, 'utf8');
    
    // Find functions starting with abcd_, efgh_, ijkl_, mnop_
    const fnRegex = /(?:function\s+|const\s+|let\s+|var\s+|async\s+function\s+)([a-z]{4}_[a-zA-Z0-9_]+)/g;
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

    // Find requires
    const reqRegex = /require\(['"]([^'"]+)['"]\)/g;
    let r;
    const fileModules = new Set();
    while ((r = reqRegex.exec(content)) !== null) {
      const mod = r[1].startsWith('.') ? path.basename(r[1]) : r[1];
      modulesUsed.add(mod);
      fileModules.add(mod);
    }

    console.log('  - ' + file.padEnd(30) + ' | ' + matches.size + ' functions | imports: ' + Array.from(fileModules).slice(0, 3).join(', '));
  }
}

console.log('\n===============================================================');
console.log('Total Subsystem Files: ' + totalFiles + ' / 50');
console.log('Total Structured Functions: ' + totalFunctions);
console.log('Syntax Errors: ' + syntaxErrors.length);
if (syntaxErrors.length > 0) {
  syntaxErrors.forEach(e => console.error('  Syntax error in ' + e.file + ': ' + e.error));
}
console.log('Function Count Deviations (<5 or >6): ' + functionCountErrors.length);
if (functionCountErrors.length > 0) {
  functionCountErrors.forEach(e => console.error('  Function deviation in ' + e.file + ': ' + e.count));
}

const target15 = [
  'crypto-js', 'jsonwebtoken', 'bcrypt', 'node-forge', 'ssh2',
  'axios', 'got', 'express', 'mongodb', 'mysql2',
  'pg', 'ioredis', 'openai', '@google-cloud/storage', 'cheerio'
];

console.log('\n--- 15 TARGET MODULES AUDIT ---');
const found = target15.filter(m => modulesUsed.has(m));
const missing = target15.filter(m => !modulesUsed.has(m));
console.log('Target Modules Found (' + found.length + '/15): ' + found.join(', '));
if (missing.length > 0) {
  console.log('Missing Target Modules: ' + missing.join(', '));
} else {
  console.log('ALL 15 TARGET MODULES FOUND IN REQUIRES!');
}
console.log('===============================================================');
