#!/usr/bin/env node
// Cài rea-flow bằng một lệnh: `skills add` (vercel-labs/skills), chép "Quy tắc bắt buộc" vào CLAUDE.md/AGENTS.md
// đúng phạm vi vừa cài (toàn máy hoặc project hiện tại), rồi kiểm và cài công cụ phân tích (flow.py setup).
// skills CLI không có post-install hook nên các bước sau nằm ở đây.
//   npx github:thaoht2109/rea-workflow [-g] [-a claude-code -a codex ...] [-y] [--no-tools] [--no-ghidra]
//     tham số khác chuyển nguyên cho `skills add`. Công cụ thiếu: hỏi trước khi cài (apt cần sudo, Ghidra ~550 MiB);
//     -y cài luôn không hỏi; --no-tools chỉ kiểm; không có terminal tương tác mà không -y thì chỉ kiểm.
//   npx github:thaoht2109/rea-workflow remove [-g]                               gỡ quy tắc rồi gỡ skill
import { spawnSync } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createInterface } from 'node:readline/promises';

const REPO = 'thaoht2109/rea-workflow', SKILLS = 'skills@1.7.4';   // bản skills CLI đã kiểm
const OWN = ['--no-tools', '--no-ghidra'];   // tham số của bộ cài này, không chuyển cho skills CLI
const all = process.argv.slice(2), args = all.filter(a => !OWN.includes(a)), remove = args[0] === 'remove', rest = remove ? args.slice(1) : args;
const yes = rest.includes('-y') || rest.includes('--yes'), noTools = all.includes('--no-tools'), noGhidra = all.includes('--no-ghidra');
const global = rest.includes('-g') || rest.includes('--global');
const run = (cmd, a) => { const r = spawnSync(cmd, a, { stdio: 'inherit', env: { DISABLE_TELEMETRY: '1', ...process.env } }); return r.error ? 127 : r.status ?? 1; };
const roots = global ? [homedir()] : [process.cwd(), homedir()];   // không -g: CLI có thể vẫn hỏi và cài toàn máy
const skillDir = () => roots.flatMap(r => ['.agents', '.claude'].map(d => join(r, d, 'skills', 'rea-flow')))
  .filter(p => existsSync(join(p, 'flow.py'))).sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0];
const rules = (dir, extra) => {
  if (run('python3', [join(dir, 'flow.py'), 'rules', ...extra]) === 127) console.error('Cần python3 để chép quy tắc.');
};

if (remove) {
  const dir = skillDir();
  if (dir) rules(dir, ['--remove']);
  process.exit(run('npx', ['-y', SKILLS, 'remove', 'rea-flow', ...rest]));
}
const rc = run('npx', ['-y', SKILLS, 'add', REPO, ...rest]);
if (rc) process.exit(rc);
const dir = skillDir();
if (!dir) { console.error('Không tìm thấy skill vừa cài: chạy tay `python3 <thư mục skill>/flow.py rules`.'); process.exit(1); }
rules(dir, []);   // phạm vi tự theo nơi skill nằm: ~/.<agent>/skills -> toàn máy, <project>/.<agent>/skills -> project
const flow = join(dir, 'flow.py'), extra = noGhidra ? ['--no-ghidra'] : [];
console.log(`\nrea-flow đã cài tại ${dir}. Kiểm công cụ phân tích:\n`);
if (run('python3', [flow, 'setup', ...extra]) !== 0) {   // mã 1 = còn thiếu, đã in kế hoạch cài
  let go = !noTools && yes;
  if (!noTools && !yes && process.stdin.isTTY) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    go = /^(|y|yes|c|có)$/i.test((await rl.question('\nCài các công cụ còn thiếu theo kế hoạch trên? [Y/n] ')).trim()); rl.close();
  }
  if (go) process.exit(run('python3', [flow, 'setup', '--yes', ...extra]));
  console.log(`\nChưa cài công cụ. Khi sẵn sàng: python3 ${flow} setup --yes`);
}
console.log(`Kiểm cấu hình: python3 ${flow} doctor`);
