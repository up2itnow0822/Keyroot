import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
const files = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
const patterns = [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, /\bgh[pousr]_[A-Za-z0-9]{30,}/, /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,}/];
const bad = files.filter(p => !/\.(png|jpg|jpeg|webp|woff2?)$/.test(p)).filter(p => patterns.some(re => re.test(readFileSync(p, 'utf8'))));
if (bad.length) throw new Error(`Potential secret material in: ${bad.join(', ')}`);
console.log(`Scanned ${files.length} tracked files; heuristic scan does not establish absence of every secret.`);
