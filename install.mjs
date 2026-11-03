#!/usr/bin/env node
// Cài rea-flow bằng một lệnh: `skills add` (vercel-labs/skills), chép "Quy tắc bắt buộc" vào CLAUDE.md/AGENTS.md
// đúng phạm vi vừa cài (toàn máy hoặc project hiện tại), rồi kiểm và cài công cụ phân tích (flow.py setup).
// skills CLI không có post-install hook nên các bước sau nằm ở đây.
//   npx github:thaoht2109/rea-workflow [-g] [-a claude-code -a codex ...] [-y] [--no-tools] [--no-ghidra]
//     tham số khác chuyển nguyên cho `skills add`. Công cụ thiếu: hỏi trước khi cài (apt cần sudo, Ghidra ~550 MiB);
//     -y cài luôn không hỏi; --no-tools chỉ kiểm; không có terminal tương tác mà không -y thì chỉ kiểm.
//   npx github:thaoht2109/rea-workflow update [-g] [-y] [--to vX.Y.Z] [--no-tools] [--no-ghidra]  kéo bản mới nhất của main
//     (skills update, hoặc git pull nếu skill là bản clone git) hay đúng bản đã gắn tag (--to: lên hoặc hạ), chép lại quy tắc, kiểm công cụ
//   npx github:thaoht2109/rea-workflow version [-g]                              bản đang cài và các bản có trên GitHub
//   npx github:thaoht2109/rea-workflow remove [-g]                               gỡ quy tắc rồi gỡ skill
import { spawnSync } from 'node:child_process';
import { existsSync, statSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createInterface } from 'node:readline/promises';

const REPO = 'thaoht2109/rea-workflow', SKILLS = 'skills@1.7.4';   // bản skills CLI đã kiểm
const OWN = ['--no-tools', '--no-ghidra'];   // tham số của bộ cài này, không chuyển cho skills CLI
const all = process.argv.slice(2), ti = all.indexOf('--to'), to = ti < 0 ? '' : all[ti + 1] ?? '';
const args = all.filter((a, i) => !OWN.includes(a) && (ti < 0 || (i !== ti && i !== ti + 1)));
const sub = ['remove', 'update', 'version'].includes(args[0]) ? args[0] : 'add', rest = sub === 'add' ? args : args.slice(1);
const yes = rest.includes('-y') || rest.includes('--yes'), noTools = all.includes('--no-tools'), noGhidra = all.includes('--no-ghidra');
const global = rest.includes('-g') || rest.includes('--global');
const run = (cmd, a, stdio = 'inherit') => { const r = spawnSync(cmd, a, { stdio, env: { DISABLE_TELEMETRY: '1', ...process.env } }); return r.error ? 127 : r.status ?? 1; };
const roots = global ? [homedir()] : [process.cwd(), homedir()];   // không -g: CLI có thể vẫn hỏi và cài toàn máy
const skillDir = () => roots.flatMap(r => ['.agents', '.claude'].map(d => join(r, d, 'skills', 'rea-flow')))
  .filter(p => existsSync(join(p, 'flow.py'))).sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0];
const lockRef = dir => {   // ref đang ghim trong lock của skills CLI (project: <project>/skills-lock.json, toàn máy: ~/.agents)
  for (const p of [join(dir, '..', '..', '..', 'skills-lock.json'), join(homedir(), '.agents', '.skill-lock.json')]) {
    try { const e = JSON.parse(readFileSync(p, 'utf8')).skills?.['rea-flow']; if (e) return e.ref || ''; } catch {}
  }
  return '';
};
const rules = (dir, extra) => {
  if (run('python3', [join(dir, 'flow.py'), 'rules', ...extra]) === 127) console.error('Cần python3 để chép quy tắc.');
};

if (sub === 'remove') {
  const dir = skillDir();
  if (dir) rules(dir, ['--remove']);
  process.exit(run('npx', ['-y', SKILLS, 'remove', 'rea-flow', ...rest]));
}
if (sub === 'version' || sub === 'update') {
  const dir = skillDir();   // skills update báo "không thấy" mà vẫn trả 0, nên kiểm trước
  if (!dir) { console.error(`Chưa cài rea-flow${global ? ' toàn máy' : ''}: npx github:${REPO} ${global ? '-g' : ''}`); process.exit(1); }
  if (sub === 'version') process.exit(run('python3', [join(dir, 'flow.py'), 'version']));
  if (ti >= 0 && !/^v?\d+\.\d+\.\d+$/.test(to)) { console.error('--to cần bản dạng vX.Y.Z (xem: npx github:' + REPO + ' version)'); process.exit(1); }
  const tag = to && (to.startsWith('v') ? to : 'v' + to);
  const git = run('git', ['-C', dir, 'rev-parse', '--is-inside-work-tree'], 'ignore') === 0;   // clone git: skills CLI không quản
  const G = a => run('git', ['-C', dir, ...a]);
  let rc;
  if (git && tag) rc = G(['fetch', '--tags', '--quiet', 'origin']) || G(['-c', 'advice.detachedHead=false', 'checkout', '--quiet', tag]);
  else if (git) rc = (run('git', ['-C', dir, 'symbolic-ref', '-q', 'HEAD'], 'ignore') ? G(['checkout', '--quiet', 'main']) : 0) || G(['pull', '--ff-only']);   // đang ghim tag thì về main
  else if (tag || lockRef(dir)) rc = run('npx', ['-y', SKILLS, 'add', REPO + (tag ? '#' + tag : ''), ...rest]);   // skills update giữ ref đang ghim nên đổi bản phải add lại
  else rc = run('npx', ['-y', SKILLS, 'update', 'rea-flow', ...rest]);
  if (rc) process.exit(rc);
} else {
  const rc = run('npx', ['-y', SKILLS, 'add', REPO, ...rest]);
  if (rc) process.exit(rc);
}
const dir = skillDir();
if (!dir) { console.error('Không tìm thấy skill vừa cài: chạy tay `python3 <thư mục skill>/flow.py rules`.'); process.exit(1); }
rules(dir, []);   // phạm vi tự theo nơi skill nằm: ~/.<agent>/skills -> toàn máy, <project>/.<agent>/skills -> project
const flow = join(dir, 'flow.py'), extra = noGhidra ? ['--no-ghidra'] : [];
console.log(`\nrea-flow đã ${sub === 'update' ? 'cập nhật' : 'cài'} tại ${dir}. Kiểm công cụ phân tích:\n`);
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
