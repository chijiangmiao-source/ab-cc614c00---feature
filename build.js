// build.js — 页面构建：语法校验 src/*.js，拷贝静态资源到 dist/，核对 HTML 引用。
import { mkdir, readdir, readFile, rm, copyFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = fileURLToPath(new URL('./src', import.meta.url));
const DIST = fileURLToPath(new URL('./dist', import.meta.url));

function syntaxCheck(file) {
  const r = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (r.status !== 0) {
    throw new Error(`语法校验失败 ${file}\n${r.stderr || r.stdout}`);
  }
}

const files = await readdir(SRC);
const jsFiles = files.filter((f) => f.endsWith('.js'));
for (const f of jsFiles) syntaxCheck(join(SRC, f));

await rm(DIST, { recursive: true, force: true });
await mkdir(DIST, { recursive: true });
for (const f of files) await copyFile(join(SRC, f), join(DIST, f));

// 核对 index.html 引用的本地资源均已产出
const html = await readFile(join(DIST, 'index.html'), 'utf8');
const refs = [...html.matchAll(/(?:src|href)="(\.\/[^"]+)"/g)].map((m) => m[1].slice(2));
for (const ref of refs) {
  await readFile(join(DIST, ref)).catch(() => {
    throw new Error(`index.html 引用的资源缺失：${ref}`);
  });
}

console.log(`build ok: ${files.length} 个文件（JS 语法校验 ${jsFiles.length} 个，HTML 引用 ${refs.length} 个）→ dist/`);
