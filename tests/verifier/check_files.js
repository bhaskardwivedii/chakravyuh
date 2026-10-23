// Run the browser verifier (docs/verify/verify.js) on real files from the command line.
//   node tests/verifier/check_files.js /tmp/chakravyuh_export.json /tmp/chakravyuh_report.json
// Exits 0 only if the log, the report and their binding all verify.
"use strict";
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..", "..");
const V = require(path.join(ROOT, "docs/verify/verify.js"));
V._setNacl(require(path.join(ROOT, "docs/verify/vendor/nacl-fast.min.js")));

(async () => {
  const [exportPath, reportPath] = process.argv.slice(2);
  if (!exportPath || !reportPath) {
    console.error("usage: node tests/verifier/check_files.js <export.json> <report.json>");
    process.exit(2);
  }
  const ex = await V.verifyExport(fs.readFileSync(exportPath, "utf8"));
  const rp = await V.verifyReport(fs.readFileSync(reportPath, "utf8"));
  const b = V.binding(ex, rp);
  const mark = (ok) => (ok ? "OK  " : "FAIL");
  console.log(`${mark(ex.chainOk)} hash chain       ${ex.records} records`);
  console.log(`${mark(ex.rootOk)} merkle root      ${ex.sealedCount} sealed, ${ex.afterSeal} after seal`);
  console.log(`${mark(ex.signatureOk)} seal signature   ${ex.engine}`);
  console.log(`${mark(rp.hashOk)} report hash`);
  console.log(`${mark(rp.signatureOk)} report signature ${rp.engine}`);
  console.log(`${mark(b.ok)} report bound to this log`);
  for (const p of ex.problems) console.log(`     - ${p.msg}`);
  console.log(`key fingerprint: ${await V.fingerprint(ex.publicKey)}`);
  const ok = ex.valid && rp.valid && b.ok;
  console.log(ok ? "result: VALID" : "result: INVALID");
  process.exit(ok ? 0 : 1);
})();
