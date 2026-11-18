#!/usr/bin/env node
// Cài rea-workflow bằng một lệnh: `skills add` (vercel-labs/skills), chép "Quy tắc bắt buộc" vào CLAUDE.md/AGENTS.md
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
import { existsSync, statSync, readFileSync, realpathSync } from 'node:fs';
import { join, basename } from 'node:path';
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
const OLD = 'rea-flow';   // tên trước 1.12: update chuyển bản cài cũ sang tên mới
const skillDir = (names = ['rea-workflow', OLD]) => roots.flatMap(r => ['.agents', '.claude', '.opencode', '.config/opencode'].flatMap(d => names.map(n => join(r, d, 'skills', n))))
  .filter(p => existsSync(join(p, 'flow.py'))).sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0];
const lockRef = dir => {   // ref đang ghim trong lock của skills CLI (project: <project>/skills-lock.json, toàn máy: ~/.agents)
  for (const p of [join(dir, '..', '..', '..', 'skills-lock.json'), join(homedir(), '.agents', '.skill-lock.json')]) {
    try { const e = JSON.parse(readFileSync(p, 'utf8')).skills?.[basename(dir)]; if (e) return e.ref || ''; } catch {}
  }
  return '';
};
const rules = (dir, extra) => {
  if (run('python3', [join(dir, 'flow.py'), 'rules', ...extra]) === 127) console.error('Cần python3 để chép quy tắc.');
};

if (sub === 'remove') {
  const dir = skillDir();
  if (dir) rules(dir, ['--remove']);
  process.exit(run('npx', ['-y', SKILLS, 'remove', dir ? basename(dir) : 'rea-workflow', ...rest]));
}
if (sub === 'version' || sub === 'update') {
  const dir = skillDir();   // skills update báo "không thấy" mà vẫn trả 0, nên kiểm trước
  if (!dir) { console.error(`Chưa cài rea-workflow${global ? ' toàn máy' : ''}: npx github:${REPO} ${global ? '-g' : ''}`); process.exit(1); }
  if (sub === 'version') process.exit(run('python3', [join(dir, 'flow.py'), 'version']));
  if (ti >= 0 && !/^v?\d+\.\d+\.\d+$/.test(to)) { console.error('--to cần bản dạng vX.Y.Z (xem: npx github:' + REPO + ' version)'); process.exit(1); }
  const tag = to && (to.startsWith('v') ? to : 'v' + to);
  const git = run('git', ['-C', dir, 'rev-parse', '--is-inside-work-tree'], 'ignore') === 0;   // clone git: skills CLI không quản
  const G = a => run('git', ['-C', dir, ...a]);
  const [M, m] = tag ? tag.slice(1).split('.').map(Number) : [];
  if (tag && !git && (M < 1 || (M === 1 && m < 12))) {   // trước 1.12 skill tên rea-flow: skills add sẽ cài thêm một skill song song
    console.error(`Bản ${tag} còn mang tên ${OLD}; hạ bản qua skills CLI sẽ cài hai skill song song. Gỡ rồi cài bản cũ:\n  npx github:${REPO} remove ${global ? '-g' : ''}\n  npx github:${REPO}#${tag} ${global ? '-g' : ''}`);
    process.exit(1);
  }
  let rc;
  if (git && tag) rc = G(['fetch', '--tags', '--quiet', 'origin']) || G(['-c', 'advice.detachedHead=false', 'checkout', '--quiet', tag]);
  else if (git) rc = (run('git', ['-C', dir, 'symbolic-ref', '-q', 'HEAD'], 'ignore') ? G(['checkout', '--quiet', 'main']) : 0) || G(['pull', '--ff-only']);   // đang ghim tag thì về main
  else if (tag || lockRef(dir) || basename(dir) === OLD) {   // skills update giữ ref đang ghim nên đổi bản phải add lại; bản tên cũ: add tên mới rồi gỡ tên cũ
    const old = realpathSync(dir);
    rc = run('npx', ['-y', SKILLS, 'add', REPO + (tag ? '#' + tag : ''), ...rest]);
    if (!rc && basename(dir) === OLD) {   // chuyển khối shell + quy tắc workspace sang bản mới rồi mới gỡ bản cũ
      const nd = skillDir(['rea-workflow']);
      if (!nd) { console.error(`Không thấy bản rea-workflow vừa cài: giữ bản cũ tại ${dir}.`); process.exit(1); }
      rc = run('python3', [join(nd, 'flow.py'), 'session', '--migrate', old]) || run('npx', ['-y', SKILLS, 'remove', OLD, ...rest]);
      if (rc) { console.error(`Chưa chuyển xong ${OLD} -> rea-workflow (bản cũ còn ở ${dir}). Xử lý tay:\n  python3 ${join(nd, 'flow.py')} session --migrate ${old}\n  npx -y ${SKILLS} remove ${OLD} ${global ? '-g' : ''}`); process.exit(rc); }
      console.log(`Đã chuyển ${OLD} -> rea-workflow. Workspace từng chạy tay rules --project thì chạy lại: python3 ${join(nd, 'flow.py')} rules --project <thư mục>`);
    }
  } else rc = run('npx', ['-y', SKILLS, 'update', 'rea-workflow', ...rest]);
  if (rc) process.exit(rc);
} else {
  const rc = run('npx', ['-y', SKILLS, 'add', REPO, ...rest]);
  if (rc) process.exit(rc);
}
const dir = skillDir();
if (!dir) { console.error('Không tìm thấy skill vừa cài: chạy tay `python3 <thư mục skill>/flow.py rules`.'); process.exit(1); }
rules(dir, []);   // phạm vi tự theo nơi skill nằm: ~/.<agent>/skills -> toàn máy, <project>/.<agent>/skills -> project
const flow = join(dir, 'flow.py'), extra = noGhidra ? ['--no-ghidra'] : [];
console.log(`\nrea-workflow đã ${sub === 'update' ? 'cập nhật' : 'cài'} tại ${dir}. Kiểm công cụ phân tích:\n`);
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
