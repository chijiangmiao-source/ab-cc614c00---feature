// der.js — 最小 DER 读取器。
// 设计要点：每个元素都保留 raw（完整 TLV 字节），
// 以便上层保留待验签的原始 TBSCertificate 字节。

export class DerError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DerError';
  }
}

// 读取 buf 中 pos 处的一个 TLV 元素。
// 返回 { tagClass, constructed, tag, value, raw, next }。
export function readElement(buf, pos = 0) {
  if (!(buf instanceof Uint8Array)) buf = new Uint8Array(buf);
  if (pos >= buf.length) throw new DerError('DER 截断：缺少标签字节');
  const first = buf[pos];
  const tagClass = (first & 0xc0) >> 6; // 0 universal / 1 application / 2 context / 3 private
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  let p = pos + 1;
  if (tag === 0x1f) { // 高标签号形式
    tag = 0;
    for (;;) {
      if (p >= buf.length) throw new DerError('DER 截断：高标签号不完整');
      const b = buf[p++];
      tag = tag * 128 + (b & 0x7f);
      if ((b & 0x80) === 0) break;
    }
  }
  if (p >= buf.length) throw new DerError('DER 截断：缺少长度字节');
  let len = buf[p++];
  if (len === 0x80) throw new DerError('DER 非法：不接受不定长编码（非 DER）');
  if ((len & 0x80) !== 0) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new DerError('DER 非法：长度字节数异常');
    if (p + n > buf.length) throw new DerError('DER 截断：长度字段不完整');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
    if (len < 128) throw new DerError('DER 非法：非最短长度编码');
  }
  if (p + len > buf.length) {
    throw new DerError(`DER 截断：声明 ${len} 字节内容，仅剩 ${buf.length - p} 字节`);
  }
  return {
    tagClass,
    constructed,
    tag,
    value: buf.subarray(p, p + len),
    raw: buf.slice(pos, p + len), // 拷贝，独立于原缓冲
    next: p + len,
  };
}

// 迭代一个构造元素的全部子元素。
export function children(el) {
  const out = [];
  let pos = 0;
  while (pos < el.value.length) {
    const child = readElement(el.value, pos);
    out.push(child);
    pos = child.next;
  }
  return out;
}

export function expect(el, tagClass, tag, what) {
  if (el.tagClass !== tagClass || el.tag !== tag) {
    throw new DerError(`DER 结构错误：期望 ${what}（实际 class=${el.tagClass} tag=${el.tag}）`);
  }
  return el;
}

export function oidString(value) {
  if (value.length === 0) throw new DerError('OID 为空');
  const first = value[0];
  const arc0 = first < 40 ? 0 : first < 80 ? 1 : 2;
  const parts = [arc0, first - 40 * arc0];
  let acc = 0;
  let pending = false;
  for (let i = 1; i < value.length; i++) {
    const b = value[i];
    acc = acc * 128 + (b & 0x7f);
    pending = (b & 0x80) !== 0;
    if (!pending) {
      parts.push(acc);
      acc = 0;
    }
  }
  if (pending) throw new DerError('OID 截断');
  return parts.join('.');
}

// 非负 INTEGER → number（仅用于 version / pathLen 等小整数）。
export function intValue(value) {
  if (value.length === 0) throw new DerError('INTEGER 为空');
  if (value.length > 6) throw new DerError('INTEGER 超出预期范围');
  let n = 0;
  for (const b of value) n = n * 256 + b;
  return n;
}

export function bitString(value) {
  if (value.length < 1) throw new DerError('BIT STRING 为空');
  return { unused: value[0], bytes: value.subarray(1) };
}

// DER 编码的 ECDSA 签名（SEQUENCE { r INTEGER, s INTEGER }）
// 转换为 WebCrypto 需要的 raw 格式（r || s，各 size 字节，左侧补零）。
export function derEcdsaToRaw(sigDer, size) {
  const seq = readElement(sigDer, 0);
  if (seq.tagClass !== 0 || seq.tag !== 16) throw new DerError('ECDSA 签名应为 SEQUENCE');
  if (seq.next !== sigDer.length) throw new DerError('ECDSA 签名存在尾随字节');
  const parts = children(seq);
  if (parts.length !== 2) throw new DerError('ECDSA 签名应包含 r、s 两个 INTEGER');
  const out = new Uint8Array(size * 2);
  parts.forEach((part, i) => {
    if (part.tagClass !== 0 || part.tag !== 2) throw new DerError('ECDSA 签名 r/s 应为 INTEGER');
    let v = part.value;
    if (v.length === 0) throw new DerError('ECDSA 签名整数为空');
    if (v.length > 1 && v[0] === 0x00) v = v.subarray(1); // 去掉 DER 符号填充字节
    if (v.length > size) throw new DerError('ECDSA 签名整数长度超过曲线阶');
    out.set(v, i * size + (size - v.length));
  });
  return out;
}

export function toHex(buf) {
  let s = '';
  for (const b of buf) s += b.toString(16).padStart(2, '0');
  return s;
}
