#!/usr/bin/env node
// Cài rea-flow bằng một lệnh: `skills add` (vercel-labs/skills) rồi chép "Quy tắc bắt buộc" vào CLAUDE.md/AGENTS.md
// đúng phạm vi vừa cài (toàn máy hoặc project hiện tại). skills CLI không có post-install hook nên bước 2 nằm ở đây.
//   npx github:thaoht2109/rea-flow [-g] [-a claude-code -a codex ...] [-y]   tham số chuyển nguyên cho `skills add`
//   npx github:thaoht2109/rea-flow remove [-g]                               gỡ quy tắc rồi gỡ skill
import { spawnSync } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const REPO = 'thaoht2109/rea-flow', SKILLS = 'skills@1.7.4';   // bản skills CLI đã kiểm
const args = process.argv.slice(2), remove = args[0] === 'remove', rest = remove ? args.slice(1) : args;
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
console.log(`\nrea-flow đã cài tại ${dir}. Kiểm công cụ: python3 ${join(dir, 'flow.py')} doctor`);
