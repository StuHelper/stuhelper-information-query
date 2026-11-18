import fs from 'node:fs';
import YAML from 'yaml';
import assert from 'node:assert/strict';

const ignoredPrefixes = ['node_modules/', '.tools/', 'bin/', '.git/'];
const files = fs.readdirSync('.', { recursive: true })
  .map((f) => f.replaceAll('\\', '/'))
  .filter((f) => f.endsWith('.go') && !ignoredPrefixes.some((prefix) => f.startsWith(prefix)));

const sqlPattern = /\b(?:SELECT|INSERT\s+INTO|UPDATE\s+[a-z_]|DELETE\s+FROM|CREATE\s+TABLE)\b/i;
for (const f of files) {
  const s = fs.readFileSync(f, 'utf8');
  if (!f.startsWith('postgres/') && !f.endsWith('_test.go')) {
    assert(!sqlPattern.test(s), `SQL outside repository: ${f}`);
  }
}

const manifest = YAML.parse(fs.readFileSync('module.yaml', 'utf8'));
for (const [scenario, tests] of Object.entries(manifest.scenario_tests)) {
  assert(tests.length, `No test for ${scenario}`);
  for (const reference of tests) {
    const [file, name] = reference.split('#');
    assert(fs.readFileSync(file, 'utf8').includes(`func ${name}(`), `Missing scenario test: ${reference}`);
  }
}
console.log('PASS: repository SQL boundary and registered scenario functions');
