// certgen.js — 测试夹具：最小 DER 编码器 + P-256 ECDSA/SHA-256 证书构造器。
// 仅用于测试，生成与被测解析器/验证器相对应的真实签名证书。
import { generateKeyPairSync, sign } from 'node:crypto';

// ---------- DER 编码 ----------

function concat(parts) {
  const len = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function lenBytes(n) {
  if (n < 128) return Uint8Array.of(n);
  const b = [];
  while (n > 0) {
    b.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Uint8Array.of(0x80 | b.length, ...b);
}

export function tlv(tag, ...contents) {
  const c = concat(contents);
  return concat([Uint8Array.of(tag), lenBytes(c.length), c]);
}

export const SEQ = (...c) => tlv(0x30, ...c);
export const SET = (...c) => tlv(0x31, ...c);

export const INT = (n) => {
  const b = [];
  let x = n;
  if (x === 0) b.push(0);
  while (x > 0) {
    b.unshift(x & 0xff);
    x = Math.floor(x / 256);
  }
  if (b[0] & 0x80) b.unshift(0);
  return tlv(0x02, Uint8Array.from(b));
};

function base128(n) {
  const b = [n & 0x7f];
  n = Math.floor(n / 128);
  while (n > 0) {
    b.unshift((n & 0x7f) | 0x80);
    n = Math.floor(n / 128);
  }
  return b;
}

export const OID = (s) => {
  const parts = s.split('.').map(Number);
  return tlv(0x06, Uint8Array.from([40 * parts[0] + parts[1], ...parts.slice(2).flatMap(base128)]));
};

export const BOOL = (v) => tlv(0x01, Uint8Array.of(v ? 0xff : 0x00));
export const OCT = (bytes) => tlv(0x04, bytes);
export const BITS = (bytes, unused = 0) => tlv(0x03, Uint8Array.of(unused), bytes);

const te = new TextEncoder();
export const UTF8 = (s) => tlv(0x0c, te.encode(s));
export const EXPL = (n, ...c) => tlv(0xa0 + n, ...c);
export const DNSNAME = (s) => tlv(0x82, te.encode(s)); // dNSName [2] IA5String（IMPLICIT）

const p2 = (n) => String(n).padStart(2, '0');
const fmtUtc = (d) =>
  `${p2(d.getUTCFullYear() % 100)}${p2(d.getUTCMonth() + 1)}${p2(d.getUTCDate())}` +
  `${p2(d.getUTCHours())}${p2(d.getUTCMinutes())}${p2(d.getUTCSeconds())}Z`;
export const UTCTIME = (d) => tlv(0x17, te.encode(fmtUtc(d)));

const NAME = (cn) => SEQ(SET(SEQ(OID('2.5.4.3'), UTF8(cn))));

// 扩展：critical 为 false 时按 DER 省略 DEFAULT FALSE 的 BOOLEAN。
export function extn(oid, critical, valueDer) {
  return critical ? SEQ(OID(oid), BOOL(true), OCT(valueDer)) : SEQ(OID(oid), OCT(valueDer));
}

function keyUsageValue({ digitalSignature, keyEncipherment, keyCertSign, crlSign }) {
  let b0 = 0;
  if (digitalSignature) b0 |= 0x80;
  if (keyEncipherment) b0 |= 0x20;
  if (keyCertSign) b0 |= 0x04;
  if (crlSign) b0 |= 0x02;
  let unused = 0;
  for (let t = b0; (t & 1) === 0 && unused < 8; t >>= 1) unused++;
  return BITS(Uint8Array.of(b0), b0 === 0 ? 0 : unused);
}

// ---------- 证书构造 ----------

export function makeKeys() {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

// 生成一张 v3 / P-256 / ECDSA-SHA256 证书（DER Uint8Array）。
export function makeCert(opts) {
  const {
    subjectCN,
    issuerCN,
    subjectPubKey,
    issuerPrivKey,
    isCA = false,
    pathLen = null,
    keyUsage = null, // {digitalSignature, keyEncipherment, keyCertSign, crlSign}
    sanDns = [],
    nameConstraints = null, // {permitted: [], excluded: []}
    notBefore = new Date('2026-01-01T00:00:00Z'),
    notAfter = new Date('2027-01-01T00:00:00Z'),
    serial = 1,
    extraExtensions = [],
    tamperSig = false,
  } = opts;

  const spki = new Uint8Array(subjectPubKey.export({ format: 'der', type: 'spki' }));

  const exts = [];
  if (isCA) {
    const bc = [BOOL(true)];
    if (pathLen !== null) bc.push(INT(pathLen));
    exts.push(extn('2.5.29.19', true, SEQ(...bc)));
  }
  if (keyUsage) exts.push(extn('2.5.29.15', true, keyUsageValue(keyUsage)));
  if (sanDns.length > 0) exts.push(extn('2.5.29.17', false, SEQ(...sanDns.map(DNSNAME))));
  if (nameConstraints) {
    const nc = [];
    if (nameConstraints.permitted && nameConstraints.permitted.length > 0) {
      nc.push(tlv(0xa0, ...nameConstraints.permitted.map((d) => SEQ(DNSNAME(d)))));
    }
    if (nameConstraints.excluded && nameConstraints.excluded.length > 0) {
      nc.push(tlv(0xa2, ...nameConstraints.excluded.map((d) => SEQ(DNSNAME(d)))));
    }
    exts.push(extn('2.5.29.30', true, SEQ(...nc)));
  }
  exts.push(...extraExtensions);

  const tbs = SEQ(
    EXPL(0, INT(2)), // version v3
    INT(serial),
    SEQ(OID('1.2.840.10045.4.3.2')), // ecdsa-with-SHA256
    NAME(issuerCN),
    SEQ(UTCTIME(notBefore), UTCTIME(notAfter)),
    NAME(subjectCN),
    spki,
    EXPL(3, SEQ(...exts)),
  );

  const sig = new Uint8Array(sign('sha256', Buffer.from(tbs), issuerPrivKey)); // DER 格式
  if (tamperSig) sig[sig.length - 1] ^= 0x01;

  return SEQ(tbs, SEQ(OID('1.2.840.10045.4.3.2')), BITS(sig, 0));
}
