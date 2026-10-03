// worker.js — 在 Worker 线程中执行链构造与逐级核验，避免阻塞页面。
import { verifyChainSet } from './chain.js';

self.onmessage = async (e) => {
  const { id, anchorDer, certDers, dnsName, verifyTime } = e.data || {};
  try {
    const result = await verifyChainSet({ anchorDer, certDers, dnsName, verifyTime });
    self.postMessage({ id, result });
  } catch (err) {
    self.postMessage({
      id,
      result: {
        ok: false,
        stage: 'internal',
        level: null,
        label: null,
        message: `内部错误：${(err && err.message) || err}`,
      },
    });
  }
};
