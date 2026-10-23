// Tests for the browser verifier (docs/verify/verify.js).
// Run:  node --test tests/verifier/verify.test.js
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..", "..");
const V = require(path.join(ROOT, "docs/verify/verify.js"));
const nacl = require(path.join(ROOT, "docs/verify/vendor/nacl-fast.min.js"));
V._setNacl(nacl);

const FX = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures.json"), "utf8"));
const ctx = { window: {} };
vm.runInNewContext(fs.readFileSync(path.join(ROOT, "docs/verify/samples.js"), "utf8"), ctx);
const S = ctx.window.CHAK_SAMPLES;
const enc = (s) => new TextEncoder().encode(s);

// ---- byte parity with Python ------------------------------------------------
test("canonical JSON matches Python byte-for-byte (ASCII and UTF-8 sources)", async () => {
  for (const c of FX.canonical) {
    for (const src of [c.source_ascii, c.source_utf8]) {
      const out = V.canonical(V.parse(src));
      assert.equal(out, c.canonical, `source: ${src}`);
      assert.equal(await V.sha256hex(enc(out)), c.sha256);
    }
  }
});

test("pure-JS SHA-256 equals WebCrypto on block-boundary lengths", async () => {
  for (const n of [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 128, 300, 1000]) {
    const b = new Uint8Array(n).map((_, i) => (i * 31 + n) & 255);
    assert.equal(V.toHex(V.sha256js(b)), await V.sha256hex(b), `length ${n}`);
  }
});

test("Merkle root matches Python for 0..7 leaves (odd duplication)", async () => {
  for (const m of FX.merkle) assert.equal(await V.merkleRoot(m.leaves), m.root);
});

test("record hash matches Python (keeps 50.0 and non-ASCII exact)", async () => {
  const r = FX.record_hash[0], o = V.parse(r.source);
  assert.equal(await V.recordHash(o.prev, o.seq, o.ts, o.event), r.hash);
});

test("Ed25519: WebCrypto and tweetnacl fallback both verify; wrong message fails", async () => {
  const e = FX.ed25519, msg = V.fromHex(e.message_hex);
  assert.equal((await V.ed25519Verify(e.public_key, e.signature, msg)).ok, true);
  V._forceFallback(true);
  const fb = await V.ed25519Verify(e.public_key, e.signature, msg);
  V._forceFallback(false);
  assert.equal(fb.ok, true); assert.equal(fb.engine, "tweetnacl");
  const bad = msg.slice(); bad[0] ^= 1;
  assert.equal((await V.ed25519Verify(e.public_key, e.signature, bad)).ok, false);
});

// ---- the real samples shipped on the page ------------------------------------
test("genuine log from a real run verifies and reconstructs the finding", async () => {
  const r = await V.verifyExport(S.export_genuine);
  assert.equal(r.valid, true, JSON.stringify(r.problems));
  assert.equal(r.records, 27); assert.equal(r.sealedCount, 24); assert.equal(r.afterSeal, 3);
  const f = r.finding[0];
  assert.equal(f.attacks, 6); assert.equal(f.blocked, 3); assert.equal(f.block_rate, 0.5);
  assert.equal(f.commitment_verified, true); assert.equal(f.closed, true);
});

test("number text survives parsing (50.0 is not rewritten to 50)", () => {
  const rec = V.parse(S.export_genuine).records[0];
  assert.match(V.canonical(rec.detail), /"quantum_ms":50\.0/);
});

test("tampered log: the flipped record is pinpointed", async () => {
  const r = await V.verifyExport(S.export_tampered);
  assert.equal(r.valid, false); assert.equal(r.chainOk, false);
  const p = r.problems.find((x) => x.kind === "content");
  assert.equal(p.seq, S.meta.flipped_seq);
  assert.equal(r.finding[0].blocked, 2);           // what the forger wanted you to believe
});

test("genuine report verifies; tampered report fails on its hash", async () => {
  const g = await V.verifyReport(S.report_genuine);
  assert.equal(g.valid, true); assert.equal(g.fields.canary_leaks, 0);
  const t = await V.verifyReport(S.report_tampered);
  assert.equal(t.valid, false); assert.equal(t.hashOk, false); assert.equal(t.fields.canary_leaks, 5);
});

test("genuine report is bound to genuine log (same key, same audit root)", async () => {
  const b = V.binding(await V.verifyExport(S.export_genuine), await V.verifyReport(S.report_genuine));
  assert.equal(b.ok, true);
});

// ---- attacks on a genuine log -------------------------------------------------
const fresh = () => V.parse(S.export_genuine);
const kinds = (r) => r.problems.map((p) => p.kind);

test("deleting a record is detected", async () => {
  const e = fresh(); e.records.splice(5, 1);
  const r = await V.verifyExport(e);
  assert.equal(r.valid, false); assert.ok(kinds(r).includes("order"));
});

test("reordering two records is detected", async () => {
  const e = fresh(); [e.records[4], e.records[5]] = [e.records[5], e.records[4]];
  assert.equal((await V.verifyExport(e)).valid, false);
});

test("covering tracks by re-hashing one record breaks the next link", async () => {
  const e = fresh(), k = S.meta.flipped_seq, r = e.records[k];
  r.detail.blocked = false;
  r.hash = await V.recordHash(r.prev_hash, r.seq, r.ts, { actor: r.actor, action: r.action, detail: r.detail });
  const res = await V.verifyExport(e);
  assert.equal(res.valid, false);
  assert.ok(res.problems.some((p) => p.kind === "link" && p.seq === k + 1));
});

test("re-hashing the WHOLE chain still fails: the signed Merkle root no longer matches", async () => {
  const e = fresh(); e.records[S.meta.flipped_seq].detail.blocked = false;
  let prev = V.GENESIS;
  for (const r of e.records) {
    r.prev_hash = prev;
    r.hash = await V.recordHash(prev, r.seq, r.ts, { actor: r.actor, action: r.action, detail: r.detail });
    prev = r.hash;
  }
  const res = await V.verifyExport(e);
  assert.equal(res.chainOk, true); assert.equal(res.rootOk, false); assert.equal(res.valid, false);
});

test("a forged seal signature is detected", async () => {
  const e = fresh(); e.seal.signature = "00".repeat(64);
  const r = await V.verifyExport(e);
  assert.equal(r.signatureOk, false); assert.equal(r.valid, false);
});

test("editing a record appended after the seal is still caught by the chain", async () => {
  const e = fresh(), last = e.records[e.records.length - 1];
  last.detail.leaks = new V.Num("3");
  assert.equal((await V.verifyExport(e)).valid, false);
});

test("verification works with the pure-JS SHA-256 and tweetnacl paths", async () => {
  V._forcePureJs(true); V._forceFallback(true);
  try {
    const r = await V.verifyExport(S.export_genuine);
    assert.equal(r.valid, true); assert.equal(r.engine, "tweetnacl");
    assert.equal((await V.verifyReport(S.report_genuine)).valid, true);
  } finally { V._forcePureJs(false); V._forceFallback(false); }
});
