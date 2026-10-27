// U13 installs the traceability ledger; an absent ledger is not a passing gate.
import { readFileSync } from 'node:fs';
const ledger = JSON.parse(readFileSync('docs/operations/traceability.json', 'utf8'));
for (const [prefix, count] of [['R', 83], ['AE', 28]]) {
  for (let i = 1; i <= count; i++) {
    const row = ledger[`${prefix}${i}`];
    if (!row || !['automated', 'pending-physical', 'pending-account'].includes(row.status) || !row.evidence) throw new Error(`Missing evidence for ${prefix}${i}`);
  }
}
console.log('Traceability coverage present; pending rows remain external gates.');
