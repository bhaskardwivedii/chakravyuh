/*
 * Chakravyuh — independent verifier (browser + Node).
 *
 * Re-derives everything from the exported JSON alone and trusts nothing else:
 *   - every audit record hash (hash chain), the Merkle root and its Ed25519 seal
 *   - the signed isolation report's hash and Ed25519 signature
 *   - that a report is bound to a log (same audit Merkle root and signing key)
 *   - the reconstructed finding (same logic as common/replay.py)
 *
 * Byte-exactness matters. The arena hashes Python's
 *   json.dumps(obj, sort_keys=True, separators=(",", ":"))   [ensure_ascii=True]
 * so this file re-implements that encoding exactly, and parses JSON losslessly
 * (number text is kept as written: 50.0 stays "50.0", never becomes 50).
 *
 * Mirrors common/audit.py (record_hash, merkle_root, verify_chain),
 * common/report.py (verify_report) and common/replay.py (reconstruct).
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.ChakVerify = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const GENESIS = "0".repeat(64);

  // ------------------------------------------------------------------------ //
  // Lossless JSON: numbers keep their original text
  // ------------------------------------------------------------------------ //
  class Num {
    constructor(text) { this.text = text; }
    valueOf() { return Number(this.text); }
    toString() { return this.text; }
  }

  function parse(src) {
    let i = 0;
    const err = (m) => { throw new SyntaxError(`${m} at position ${i}`); };
    const ws = () => { while (i < src.length && " \t\n\r".includes(src[i])) i++; };
    function value() {
      ws();
      const c = src[i];
      if (c === "{") return object();
      if (c === "[") return array();
      if (c === '"') return string();
      if (c === "t" && src.startsWith("true", i)) { i += 4; return true; }
      if (c === "f" && src.startsWith("false", i)) { i += 5; return false; }
      if (c === "n" && src.startsWith("null", i)) { i += 4; return null; }
      return number();
    }
    function object() {
      i++; const o = {}; ws();
      if (src[i] === "}") { i++; return o; }
      for (;;) {
        ws(); if (src[i] !== '"') err("expected string key");
        const k = string(); ws();
        if (src[i] !== ":") err("expected ':'"); i++;
        o[k] = value(); ws();
        if (src[i] === ",") { i++; continue; }
        if (src[i] === "}") { i++; return o; }
        err("expected ',' or '}'");
      }
    }
    function array() {
      i++; const a = []; ws();
      if (src[i] === "]") { i++; return a; }
      for (;;) {
        a.push(value()); ws();
        if (src[i] === ",") { i++; continue; }
        if (src[i] === "]") { i++; return a; }
        err("expected ',' or ']'");
      }
    }
    function string() {
      i++; let out = "";
      for (;;) {
        if (i >= src.length) err("unterminated string");
        const c = src[i++];
        if (c === '"') return out;
        if (c !== "\\") { out += c; continue; }
        const e = src[i++];
        if (e === "u") {
          const h = src.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(h)) err("bad \\u escape");
          out += String.fromCharCode(parseInt(h, 16)); i += 4;
        } else {
          const map = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
          if (!(e in map)) err("bad escape"); out += map[e];
        }
      }
    }
    function number() {
      const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(src.slice(i));
      if (!m) err("unexpected token");
      i += m[0].length;
      return new Num(m[0]);
    }
    const v = value(); ws();
    if (i !== src.length) err("trailing data");
    return v;
  }

  // ------------------------------------------------------------------------ //
  // Python json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)
  // ------------------------------------------------------------------------ //
  const SHORT = { "\\": "\\\\", '"': '\\"', "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t" };
  function pyString(s) {
    let out = '"';
    for (let k = 0; k < s.length; k++) {
      const ch = s[k], code = s.charCodeAt(k);   // UTF-16 code units == Python's surrogate pairs
      if (SHORT[ch]) out += SHORT[ch];
      else if (code >= 0x20 && code <= 0x7e) out += ch;
      else out += "\\u" + code.toString(16).padStart(4, "0");
    }
    return out + '"';
  }
  function canonical(v) {
    if (v === null) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (v instanceof Num) return v.text;
    if (typeof v === "number") {
      // Only reached for values built in JS. Parsed input always arrives as Num,
      // which keeps Python's exact text (e.g. "50.0"); always verify raw JSON text.
      if (!Number.isFinite(v)) throw new Error("non-finite number");
      return String(v);
    }
    if (typeof v === "string") return pyString(v);
    if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
    const keys = Object.keys(v).sort();
    return "{" + keys.map((k) => pyString(k) + ":" + canonical(v[k])).join(",") + "}";
  }

  // ------------------------------------------------------------------------ //
  // Bytes, SHA-256 (WebCrypto, with a pure-JS fallback), Ed25519
  // ------------------------------------------------------------------------ //
  const enc = (s) => new TextEncoder().encode(s);
  const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  function fromHex(h) {
    if (typeof h !== "string" || h.length % 2 || /[^0-9a-f]/i.test(h)) throw new Error("bad hex");
    const out = new Uint8Array(h.length / 2);
    for (let k = 0; k < out.length; k++) out[k] = parseInt(h.substr(k * 2, 2), 16);
    return out;
  }
  const subtle = (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) || null;

  // Pure-JS SHA-256 (FIPS 180-4) for contexts without WebCrypto.
  const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  function sha256js(bytes) {
    const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    const l = bytes.length, withPad = ((l + 9 + 63) >> 6) << 6;
    const m = new Uint8Array(withPad); m.set(bytes); m[l] = 0x80;
    const dv = new DataView(m.buffer);
    dv.setUint32(withPad - 8, Math.floor(l / 0x20000000)); dv.setUint32(withPad - 4, (l << 3) >>> 0);
    const W = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let off = 0; off < withPad; off += 64) {
      for (let t = 0; t < 16; t++) W[t] = dv.getUint32(off + t * 4);
      for (let t = 16; t < 64; t++) {
        const s0 = rotr(W[t-15], 7) ^ rotr(W[t-15], 18) ^ (W[t-15] >>> 3);
        const s1 = rotr(W[t-2], 17) ^ rotr(W[t-2], 19) ^ (W[t-2] >>> 10);
        W[t] = (W[t-16] + s0 + W[t-7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[t] + W[t]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d; H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;
    }
    const out = new Uint8Array(32), odv = new DataView(out.buffer);
    for (let t = 0; t < 8; t++) odv.setUint32(t * 4, H[t]);
    return out;
  }
  let forcePureJs = false;
  async function sha256(bytes) {
    if (subtle && !forcePureJs) return new Uint8Array(await subtle.digest("SHA-256", bytes));
    return sha256js(bytes);
  }
  const sha256hex = async (bytes) => toHex(await sha256(bytes));

  let naclLib = (typeof nacl !== "undefined") ? nacl : null;   // browser global from vendor/
  let forceFallback = false;
  async function ed25519Verify(pubHex, sigHex, msgBytes) {
    const pub = fromHex(pubHex), sig = fromHex(sigHex);
    if (pub.length !== 32 || sig.length !== 64) return { ok: false, engine: "length check" };
    if (subtle && !forceFallback) {
      try {
        const key = await subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
        return { ok: await subtle.verify({ name: "Ed25519" }, key, sig, msgBytes), engine: "WebCrypto" };
      } catch (e) { /* Ed25519 not supported here — use the vendored fallback */ }
    }
    if (naclLib) return { ok: naclLib.sign.detached.verify(msgBytes, sig, pub), engine: "tweetnacl" };
    throw new Error("No Ed25519 implementation available in this browser");
  }

  // ------------------------------------------------------------------------ //
  // Arena primitives (mirror common/audit.py)
  // ------------------------------------------------------------------------ //
  async function recordHash(prev, seq, ts, event) {
    return sha256hex(enc(canonical({ prev, seq, ts, event })));
  }
  async function merkleRoot(leaves) {
    if (!leaves.length) return GENESIS;
    let level = leaves.slice();
    while (level.length > 1) {
      if (level.length % 2 === 1) level.push(level[level.length - 1]);
      const next = [];
      for (let k = 0; k < level.length; k += 2) {
        const a = fromHex(level[k]), b = fromHex(level[k + 1]);
        const cat = new Uint8Array(64); cat.set(a); cat.set(b, 32);
        next.push(await sha256hex(cat));
      }
      level = next;
    }
    return level[0];
  }
  const num = (v) => (v instanceof Num ? Number(v.text) : Number(v));
  const asObj = (input) => (typeof input === "string" ? parse(input) : input);

  // ------------------------------------------------------------------------ //
  // Audit export (GET /audit/export)
  // ------------------------------------------------------------------------ //
  async function verifyExport(input) {
    const ex = asObj(input);
    if (!ex || !Array.isArray(ex.records)) throw new Error("Not an audit export: no 'records' array");
    const recs = ex.records, problems = [], status = [], hashes = [];
    let prev = GENESIS;
    for (let k = 0; k < recs.length; k++) {
      const r = recs[k]; let st = "ok";
      if (num(r.seq) !== k) { problems.push({ seq: num(r.seq), index: k, kind: "order", msg: `record at position ${k} has seq ${num(r.seq)} — records were removed or reordered` }); st = "bad"; }
      if (r.prev_hash !== prev) { problems.push({ seq: num(r.seq), kind: "link", msg: `record #${num(r.seq)} does not link to the record before it` }); st = "bad"; }
      const expect = await recordHash(prev, r.seq, r.ts, { actor: r.actor, action: r.action, detail: r.detail });
      if (expect !== r.hash) { problems.push({ seq: num(r.seq), kind: "content", msg: `record #${num(r.seq)} (${r.action}) was changed after it was written` }); st = "bad"; }
      status.push(st); prev = r.hash; hashes.push(r.hash);
    }
    const seal = ex.seal || null;
    let rootOk = false, sig = { ok: false, engine: "—" }, sealedCount = 0, computedRoot = null;
    if (seal) {
      sealedCount = num(seal.sealed_through_seq) + 1;
      computedRoot = await merkleRoot(hashes.slice(0, sealedCount));
      rootOk = computedRoot === seal.merkle_root;
      if (!rootOk) problems.push({ kind: "root", msg: "the Merkle root does not match the sealed records" });
      try { sig = await ed25519Verify(ex.public_key, seal.signature, fromHex(seal.merkle_root)); }
      catch (e) { sig = { ok: false, engine: String(e.message || e) }; }
      if (!sig.ok) problems.push({ kind: "signature", msg: "the Ed25519 seal signature is not valid for this public key" });
    } else {
      problems.push({ kind: "seal", msg: "the log has no seal" });
    }
    const chainOk = !problems.some((p) => ["order", "link", "content"].includes(p.kind));
    return {
      type: "export", valid: problems.length === 0, chainOk, rootOk, signatureOk: sig.ok, engine: sig.engine,
      records: recs.length, sealedCount, afterSeal: Math.max(0, recs.length - sealedCount),
      publicKey: ex.public_key, merkleRootSealed: seal ? seal.merkle_root : null,
      merkleRootAll: await merkleRoot(hashes),
      problems, status, actions: recs.map((r) => r.action), finding: reconstruct(recs),
    };
  }

  // Same grouping as common/replay.py
  function reconstruct(records) {
    const tests = {}; let current = null;
    for (const r of records) {
      const d = r.detail || {}; let tid = d.test_id;
      if (r.action === "open_test" && tid) {
        current = tid;
        tests[tid] = { test_id: tid, model_session: d.model_session, attacks: 0, blocked: 0,
          committed_hash: null, n_committed: null, commitment_verified: null, closed: false };
      }
      tid = tid || current;
      const t = tid && tests[tid];
      if (!t) continue;
      if (r.action === "commit") { t.committed_hash = d.commitment; t.n_committed = num(d.n_payloads); }
      else if (r.action === "attack_routed") { t.attacks++; t.blocked += d.blocked ? 1 : 0; }
      else if (r.action === "close_test") t.closed = true;
      else if (r.action === "reveal") t.commitment_verified = !!d.commitment_valid;
    }
    return Object.values(tests).map((t) => ({ ...t, block_rate: t.attacks ? Math.round((t.blocked / t.attacks) * 1000) / 1000 : 0 }));
  }

  // ------------------------------------------------------------------------ //
  // Signed isolation report (GET /report)
  // ------------------------------------------------------------------------ //
  async function verifyReport(input) {
    const rp = asObj(input);
    if (!rp || typeof rp.report !== "object" || !rp.signature) throw new Error("Not a signed report: needs 'report' and 'signature'");
    const recomputed = await sha256hex(enc(canonical(rp.report)));
    const hashOk = recomputed === rp.report_hash;
    let sig = { ok: false, engine: "—" };
    try { sig = await ed25519Verify(rp.public_key, rp.signature, fromHex(rp.report_hash)); }
    catch (e) { sig = { ok: false, engine: String(e.message || e) }; }
    const b = rp.report;
    return {
      type: "report", valid: hashOk && sig.ok, hashOk, signatureOk: sig.ok, engine: sig.engine,
      publicKey: rp.public_key, auditRoot: b.audit_merkle_root,
      fields: {
        test_id: b.test_id, attacks: num(b.attacks_processed), block_rate: num(b.block_rate),
        blocked: b.verdicts ? num(b.verdicts.blocked) : null,
        canary_leaks: b.canary_leaks == null ? null : num(b.canary_leaks),
        canary_probes: b.canary_probes == null ? null : num(b.canary_probes),
        commitment_verified: b.payloads_commitment_verified,
        protects: b.protects_against || [], not_protects: b.does_not_protect_against || [],
      },
    };
  }

  // A report is bound to a log when both use the same key and the report's
  // audit root equals the root over the log's records.
  function binding(exportResult, reportResult) {
    const sameKey = exportResult.publicKey === reportResult.publicKey;
    const sameRoot = reportResult.auditRoot === exportResult.merkleRootAll;
    return { ok: sameKey && sameRoot, sameKey, sameRoot };
  }

  async function fingerprint(pubHex) {
    return (await sha256hex(fromHex(pubHex))).slice(0, 16);
  }

  function detect(input) {
    const o = asObj(input);
    if (o && Array.isArray(o.records)) return "export";
    if (o && o.report && o.signature) return "report";
    return "unknown";
  }

  return {
    parse, canonical, Num, sha256hex, sha256js, toHex, fromHex, merkleRoot, recordHash,
    ed25519Verify, verifyExport, verifyReport, binding, fingerprint, detect, reconstruct, GENESIS,
    _setNacl: (lib) => { naclLib = lib; },
    _forceFallback: (v) => { forceFallback = !!v; },
    _forcePureJs: (v) => { forcePureJs = !!v; },
  };
});
