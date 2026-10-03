// x509.js — X.509 证书解析与准入校验。
// 准入规则：仅接受 X.509 v3、id-ecPublicKey / P-256、ecdsa-with-SHA256。
// 解析时保留原始 TBSCertificate 字节（tbs）供验签，保留 SPKI 原始字节供导入。

import { DerError, readElement, children, expect, oidString, intValue, bitString, toHex } from './der.js';

export class CertError extends Error {
  constructor(stage, message) {
    super(message);
    this.name = 'CertError';
    this.stage = stage; // 'parse' | 'algorithm' | 'extension'
  }
}

export const OID = {
  ecdsaSha256: '1.2.840.10045.4.3.2',
  ecPublicKey: '1.2.840.10045.2.1',
  p256: '1.2.840.10045.3.1.7',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  san: '2.5.29.17',
  nameConstraints: '2.5.29.30',
  ski: '2.5.29.14',
  aki: '2.5.29.35',
  crlNumber: '2.5.29.20',
};

// 已知但与本工具判定无关、允许忽略的扩展（即使标记 critical 也不影响链判定）。
const IGNORED_KNOWN = new Set([OID.ski, OID.aki]);

const ATTR_NAMES = {
  '2.5.4.3': 'CN',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '1.2.840.113549.1.9.1': 'E',
};

const utf8 = new TextDecoder('utf-8');

function parseNameUnchecked(el) {
  const parts = [];
  for (const rdn of children(el)) {
    for (const atv of children(rdn)) {
      const kv = children(atv);
      if (kv.length !== 2) throw new DerError('RDN 属性结构错误');
      const oid = oidString(kv[0].value);
      const key = ATTR_NAMES[oid] || oid;
      parts.push(`${key}=${utf8.decode(kv[1].value)}`);
    }
  }
  return { der: el.raw, str: parts.join(', ') || '(空名称)' };
}

export function parseName(el) {
  expect(el, 0, 16, 'Name SEQUENCE');
  return parseNameUnchecked(el);
}

export function parseTime(el) {
  const s = utf8.decode(el.value);
  let m;
  if (el.tagClass === 0 && el.tag === 23) { // UTCTime YYMMDDHHMMSSZ
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new DerError(`UTCTime 格式非法：${s}`);
    let y = Number(m[1]);
    y += y < 50 ? 2000 : 1900;
    return Date.UTC(y, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
  }
  if (el.tagClass === 0 && el.tag === 24) { // GeneralizedTime YYYYMMDDHHMMSSZ
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new DerError(`GeneralizedTime 格式非法：${s}`);
    return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
  }
  throw new DerError('有效期字段应为 UTCTime / GeneralizedTime');
}

function parseBasicConstraints(bytes) {
  const el = readElement(bytes, 0);
  expect(el, 0, 16, 'BasicConstraints SEQUENCE');
  let ca = false;
  let pathLen = null;
  for (const c of children(el)) {
    if (c.tagClass === 0 && c.tag === 1) ca = c.value[0] !== 0;
    else if (c.tagClass === 0 && c.tag === 2) pathLen = intValue(c.value);
    else throw new DerError('BasicConstraints 含未知字段');
  }
  return { ca, pathLen };
}

function parseKeyUsage(bytes) {
  const el = readElement(bytes, 0);
  expect(el, 0, 3, 'KeyUsage BIT STRING');
  const { bytes: bits } = bitString(el.value);
  const b0 = bits.length > 0 ? bits[0] : 0;
  return {
    digitalSignature: (b0 & 0x80) !== 0, // bit 0
    keyEncipherment: (b0 & 0x20) !== 0,  // bit 2
    keyCertSign: (b0 & 0x04) !== 0,      // bit 5
    cRLSign: (b0 & 0x02) !== 0,          // bit 6
  };
}

function parseSan(bytes) {
  const el = readElement(bytes, 0);
  expect(el, 0, 16, 'GeneralNames SEQUENCE');
  const dns = [];
  for (const gn of children(el)) {
    if (gn.tagClass === 2 && gn.tag === 2) dns.push(utf8.decode(gn.value)); // dNSName [2] IA5String
  }
  return { dns };
}

function parseNameConstraints(bytes) {
  const el = readElement(bytes, 0);
  expect(el, 0, 16, 'NameConstraints SEQUENCE');
  const permitted = [];
  const excluded = [];
  for (const c of children(el)) {
    if (c.tagClass !== 2 || (c.tag !== 0 && c.tag !== 2)) throw new DerError('NameConstraints 含未知字段');
    const list = c.tag === 0 ? permitted : excluded;
    for (const subtree of children(c)) { // GeneralSubtree
      const base = readElement(subtree.value, 0);
      if (base.tagClass === 2 && base.tag === 2) list.push(utf8.decode(base.value)); // 仅处理 dNSName 形式
    }
  }
  return { permitted, excluded };
}

function parseExtensions(el) {
  const ext = {
    basicConstraints: null, // {ca, pathLen, critical}
    keyUsage: null,         // {digitalSignature, keyCertSign, ..., critical}
    san: null,              // {dns: [], critical}
    nameConstraints: null,  // {permitted: [], excluded: [], critical}
    unknownCritical: [],
  };
  for (const extnEl of children(el)) {
    const parts = children(extnEl);
    if (parts.length < 2 || parts.length > 3) throw new DerError('扩展结构错误');
    const oid = oidString(parts[0].value);
    let critical = false;
    let valEl;
    if (parts.length === 3) {
      critical = parts[1].tagClass === 0 && parts[1].tag === 1 && parts[1].value[0] !== 0;
      valEl = parts[2];
    } else {
      valEl = parts[1];
    }
    expect(valEl, 0, 4, 'extnValue OCTET STRING');
    const v = valEl.value;
    switch (oid) {
      case OID.basicConstraints:
        ext.basicConstraints = { ...parseBasicConstraints(v), critical };
        break;
      case OID.keyUsage:
        ext.keyUsage = { ...parseKeyUsage(v), critical };
        break;
      case OID.san:
        ext.san = { ...parseSan(v), critical };
        break;
      case OID.nameConstraints:
        ext.nameConstraints = { ...parseNameConstraints(v), critical };
        break;
      default:
        if (critical && !IGNORED_KNOWN.has(oid)) ext.unknownCritical.push(oid);
    }
  }
  return ext;
}

function algOid(el) {
  expect(el, 0, 16, 'AlgorithmIdentifier SEQUENCE');
  const parts = children(el);
  if (parts.length < 1) throw new DerError('AlgorithmIdentifier 为空');
  return oidString(parts[0].value);
}

function parseSpki(el) {
  expect(el, 0, 16, 'SubjectPublicKeyInfo SEQUENCE');
  const parts = children(el);
  if (parts.length !== 2) throw new DerError('SPKI 结构错误');
  const algParts = children(parts[0]);
  if (algParts.length < 2) throw new DerError('SPKI 算法字段不完整');
  const keyAlg = oidString(algParts[0].value);
  if (keyAlg !== OID.ecPublicKey) {
    throw new CertError('algorithm', `仅接受 id-ecPublicKey 公钥（实际算法 OID ${keyAlg}）`);
  }
  const curve = oidString(algParts[1].value);
  if (curve !== OID.p256) {
    throw new CertError('algorithm', `仅接受 P-256 曲线（实际曲线 OID ${curve}）`);
  }
  expect(parts[1], 0, 3, 'subjectPublicKey BIT STRING');
  const { unused, bytes } = bitString(parts[1].value);
  if (unused !== 0 || bytes.length !== 65 || bytes[0] !== 0x04) {
    throw new DerError('P-256 公钥应为 65 字节未压缩点');
  }
  return { raw: el.raw, keyBytes: bytes };
}

// 解析一张证书；失败抛出 CertError（带 stage）。
export function parseCertificate(derBytes) {
  const der = derBytes instanceof Uint8Array ? derBytes : new Uint8Array(derBytes);
  try {
    const top = readElement(der, 0);
    expect(top, 0, 16, 'Certificate SEQUENCE');
    if (top.next !== der.length) throw new DerError('证书存在尾随字节');
    const parts = children(top);
    if (parts.length !== 3) throw new DerError('Certificate 应含 3 个字段');
    const [tbsEl, sigAlgEl, sigValEl] = parts;

    const tbsRaw = tbsEl.raw; // —— 待验签的原始 TBSCertificate 字节 ——
    const t = children(tbsEl);
    let i = 0;

    if (i >= t.length || t[i].tagClass !== 2 || t[i].tag !== 0) {
      throw new CertError('parse', '缺少版本字段：仅接受 X.509 v3');
    }
    const version = intValue(readElement(t[i].value, 0).value);
    if (version !== 2) throw new CertError('parse', `仅接受 X.509 v3（实际 v${version + 1}）`);
    i++;

    expect(t[i], 0, 2, 'serialNumber INTEGER');
    const serial = toHex(t[i].value);
    i++;

    const tbsAlg = algOid(t[i]);
    if (tbsAlg !== OID.ecdsaSha256) {
      throw new CertError('algorithm', `仅接受 ecdsa-with-SHA256 签名算法（实际 OID ${tbsAlg}）`);
    }
    i++;

    const issuer = parseName(t[i]);
    i++;

    const validity = children(t[i]);
    if (validity.length !== 2) throw new DerError('validity 结构错误');
    const notBefore = parseTime(validity[0]);
    const notAfter = parseTime(validity[1]);
    if (notAfter < notBefore) throw new DerError('有效期区间非法');
    i++;

    const subject = parseName(t[i]);
    i++;

    const spki = parseSpki(t[i]);
    i++;

    while (i < t.length && t[i].tagClass === 2 && (t[i].tag === 1 || t[i].tag === 2)) i++; // issuer/subjectUniqueID

    let extensions = {
      basicConstraints: null, keyUsage: null, san: null,
      nameConstraints: null, unknownCritical: [],
    };
    if (i < t.length) {
      if (t[i].tagClass !== 2 || t[i].tag !== 3) throw new DerError('TBSCertificate 含未知字段');
      const extSeq = readElement(t[i].value, 0);
      expect(extSeq, 0, 16, 'Extensions SEQUENCE');
      extensions = parseExtensions(extSeq);
      i++;
    }
    if (i !== t.length) throw new DerError('TBSCertificate 字段数量异常');

    const outerAlg = algOid(sigAlgEl);
    if (outerAlg !== OID.ecdsaSha256) {
      throw new CertError('algorithm', `仅接受 ecdsa-with-SHA256 签名算法（实际 OID ${outerAlg}）`);
    }
    if (outerAlg !== tbsAlg) throw new DerError('内外签名算法标识不一致');

    expect(sigValEl, 0, 3, 'signatureValue BIT STRING');
    const sig = bitString(sigValEl.value);
    if (sig.unused !== 0) throw new DerError('签名 BIT STRING 未用位非零');

    if (extensions.unknownCritical.length > 0) {
      throw new CertError('extension', `未知关键扩展：${extensions.unknownCritical.join(', ')}`);
    }

    return {
      der,
      tbs: tbsRaw,
      serial,
      issuer,
      subject,
      notBefore,
      notAfter,
      spkiRaw: spki.raw,
      signatureDer: sig.bytes.slice(),
      isCA: extensions.basicConstraints !== null && extensions.basicConstraints.ca === true,
      pathLen: extensions.basicConstraints ? extensions.basicConstraints.pathLen : null,
      keyUsagePresent: extensions.keyUsage !== null,
      keyCertSign: extensions.keyUsage !== null && extensions.keyUsage.keyCertSign === true,
      sanDns: extensions.san ? extensions.san.dns : [],
      nameConstraints: extensions.nameConstraints || { permitted: [], excluded: [] },
      label: '',
      sha256: '',
    };
  } catch (e) {
    if (e instanceof CertError) throw e;
    if (e instanceof DerError) throw new CertError('parse', e.message);
    throw new CertError('parse', `解析失败：${e && e.message}`);
  }
}
