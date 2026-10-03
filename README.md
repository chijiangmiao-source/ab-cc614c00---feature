# 离线证书链复核终端

地面接收终端接入新遥测服务证书时，安全工程师在浏览器页面中离线复核证书包：
粘贴 **1 张信任锚**、**至多 7 张无序 DER Base64 证书**、**目标 DNS 名称** 与 **验证时刻**，
提交复核或清空草稿。全部验证在本机 Web Worker 中完成，证书内容不离开浏览器。

## 准入与验证规则

- 仅接受 **X.509 v3**、**P-256（secp256r1）ECDSA / SHA-256** 证书；其他版本、曲线或签名算法直接拒绝。
- 解析时保留待验签的**原始 TBSCertificate 字节**；DER 编码的 ECDSA 签名（`SEQUENCE {r, s}`）
  被准确转换为 WebCrypto 所需的 raw 格式（`r || s`，各 32 字节补零）。
- 在 Worker 中从叶证书向信任锚 DFS 构造候选链，逐级核验：
  签名、有效期、CA 与 keyUsage（keyCertSign）、pathLenConstraint，
  以及自顶向下**累积的 DNS permitted / excluded 名称约束**（RFC 5280 语义：
  `example.com` 覆盖本身与子域，`.example.com` 仅覆盖子域）。
- 多条链成立时，按各级证书 **SHA-256 摘要字典序**（叶→锚）稳定选出一条，并展示逐级依据。
- 截断 DER、未知关键扩展、循环签发、主机名未列入 SAN、任何约束违约，
  都会定位**首个失败环节**（阶段 / 级别 / 证书标签），并清除旧成功结论。

## 本地运行

```bash
node build.js          # 页面构建：语法校验 + 产出 dist/
PORT=8080 node server.js   # 提供页面与 /health 健康响应
```

打开 `http://localhost:8080`（WebCrypto 需要安全上下文，localhost 可用）。

## Docker

```bash
docker build -t cert-review .
docker run --rm -p 8080:8080 cert-review
```

## Compose（宿主端口可配置）

```bash
HOST_PORT=9000 docker compose up web        # 页面服务，默认映射 8080
docker compose run --rm verify              # 单次验收容器，退出码即验收结果
# 或：docker compose up --exit-code-from verify verify
```

`verify` 容器依次执行：逻辑测试（有效链、permitted/excluded 受限域名拒绝、
pathLen 违约、签名篡改、循环签发、截断 DER、未知关键扩展、多链稳定选择等场景）→
页面构建 → HTTP 冒烟（页面、/health、静态资源、404），全部通过以退出码 0 退出，否则 1。

## 目录结构

```
src/der.js     最小 DER 读取器（保留原始 TLV 字节，DER→raw 签名转换）
src/x509.js    X.509 解析与准入（v3 / P-256 / ECDSA-SHA-256 / 未知关键扩展）
src/chain.js   候选链构造 + 逐级核验 + 摘要序稳定选择（浏览器与 Node 共用）
src/worker.js  Web Worker 入口
src/app.js     页面交互（草稿、提交复核、清空、结果渲染）
server.js      静态页面 + /health
build.js       页面构建（语法校验 → dist/）
test/          证书生成夹具 + 逻辑测试
verify/run.js  验收容器入口
```
