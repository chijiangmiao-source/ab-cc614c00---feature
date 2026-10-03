// verify/run.js — 单次验收容器入口：
//   1) 逻辑测试（有效链与受限域名拒绝等场景）
//   2) 页面构建（语法校验 + 产出 dist/）
//   3) HTTP 冒烟（启动服务器，检查页面与健康响应）
// 全部通过退出码 0，否则 1。
import { spawn, spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const VERIFY_PORT = Number(process.env.VERIFY_PORT || 8123);
const BASE = `http://127.0.0.1:${VERIFY_PORT}`;

const results = [];
function step(name, passed, detail = '') {
  results.push([name, passed]);
  console.log(`${passed ? 'PASS' : 'FAIL'} ${name}${detail ? ` —— ${detail}` : ''}`);
  return passed;
}

function runNode(script) {
  const r = spawnSync(process.execPath, [join(ROOT, script)], { stdio: 'inherit' });
  return r.status === 0;
}

async function waitForHealth(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return true;
    } catch { /* 尚未就绪 */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

async function smoke() {
  const server = spawn(process.execPath, [join(ROOT, 'server.js')], {
    env: { ...process.env, PORT: String(VERIFY_PORT) },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  try {
    if (!(await waitForHealth(10000))) {
      console.error('服务器未在 10s 内就绪');
      return false;
    }
    let allOk = true;

    const health = await fetch(`${BASE}/health`);
    const healthJson = await health.json();
    allOk &&= step('冒烟：GET /health 返回 ok',
      health.status === 200 && healthJson.status === 'ok');

    const page = await fetch(`${BASE}/`);
    const html = await page.text();
    allOk &&= step('冒烟：GET / 返回复核页面',
      page.status === 200 && html.includes('离线证书链复核终端'));

    for (const asset of ['/app.js', '/worker.js', '/chain.js', '/style.css']) {
      const r = await fetch(`${BASE}${asset}`);
      allOk &&= step(`冒烟：GET ${asset}`, r.status === 200);
    }

    const nf = await fetch(`${BASE}/nope-${Date.now()}`);
    allOk &&= step('冒烟：未知路径返回 404', nf.status === 404);
    return allOk;
  } finally {
    server.kill();
  }
}

console.log('== 步骤 1/3：逻辑测试 ==');
const t1 = step('逻辑测试（有效链 / 受限域名拒绝等场景）', runNode('test/run-tests.js'));

console.log('== 步骤 2/3：页面构建 ==');
const t2 = step('页面构建（语法校验 + dist 产出）', runNode('build.js'));

console.log('== 步骤 3/3：HTTP 冒烟 ==');
const t3 = step('HTTP 冒烟（页面 + 健康响应）', await smoke());

const okAll = t1 && t2 && t3;
console.log(`\n验收结果：${okAll ? '全部通过' : '存在失败项'}`);
process.exit(okAll ? 0 : 1);
