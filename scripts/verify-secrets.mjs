import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
const tracked = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
function clientFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = `${directory}/${entry.name}`;
    return entry.isDirectory() ? clientFiles(path) : entry.isFile() ? [path] : [];
  });
}
// Missing builds fail this gate: both public surfaces must be inspected after build.
const built = ['apps/review/dist/client', 'apps/review/dist/phone'].flatMap(clientFiles);
const files = [...new Set([...tracked, ...built])];
const patterns = [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, /\bgh[pousr]_[A-Za-z0-9]{30,}/, /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,}/];
const bad = files.filter(p => !/\.(png|jpg|jpeg|webp|woff2?)$/.test(p)).filter(p => patterns.some(re => re.test(readFileSync(p, 'utf8'))));
if (bad.length) throw new Error(`Potential secret material in: ${bad.join(', ')}`);
console.log(`Scanned ${tracked.length} tracked files and ${built.length} built client/phone assets; heuristic scan does not establish absence of every secret.`);
