"""
Isolation dashboard — served by the broker at `/`.

Deliberately metadata-only (vertical 7: observability that is not a leakage
channel). It renders phase, verdict counts, latency-padding stats and the canary
leakage score by polling the broker's /state and /events endpoints, which never
expose payload content or model output. Single self-contained HTML page, no
build step, no external calls — so it runs on any judge's machine.
"""

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Chakravyuh — Isolation Dashboard</title>
<style>
  :root{
    --bg:#0b0e14; --panel:#131824; --line:#232a3a; --ink:#e6eaf2; --mut:#8b95ab;
    --ok:#3fb67a; --bad:#e5564e; --warn:#e0a53f; --accent:#5b8cff; --accent2:#9a6bff;
  }
  @media (prefers-color-scheme:light){
    :root{--bg:#f6f7fb;--panel:#ffffff;--line:#e4e8f0;--ink:#121725;
          --mut:#5a6377;--ok:#1f9d57;--bad:#c53b33;--warn:#b7791f;--accent:#2f6bff;--accent2:#7b4bff;}
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
       font:15px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
  header{padding:20px 24px;border-bottom:1px solid var(--line);
         display:flex;align-items:center;gap:14px;flex-wrap:wrap}
  .logo{width:34px;height:34px;border-radius:9px;
        background:linear-gradient(135deg,var(--accent),var(--accent2));flex:0 0 auto}
  h1{font-size:18px;margin:0;letter-spacing:.2px}
  .sub{color:var(--mut);font-size:13px}
  .phase{margin-left:auto;padding:6px 14px;border-radius:999px;border:1px solid var(--line);
         font-weight:600;font-size:13px}
  main{padding:24px;max-width:1120px;margin:0 auto;
       display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}
  .card h2{font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--mut);
           margin:0 0 12px}
  .big{font-size:34px;font-weight:700;line-height:1}
  .row{display:flex;justify-content:space-between;padding:7px 0;border-top:1px solid var(--line)}
  .row:first-of-type{border-top:0}
  .k{color:var(--mut)} .v{font-variant-numeric:tabular-nums;font-weight:600}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600}
  .pill.ok{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}
  .pill.bad{background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)}
  .lanes{display:flex;gap:10px;flex-wrap:wrap}
  .lane{flex:1;min-width:120px;text-align:center;padding:14px 8px;border-radius:12px;
        border:1px dashed var(--line)}
  .lane .nm{font-weight:700;margin-bottom:4px}
  .lane .st{font-size:12px;color:var(--ok)}
  .feed{grid-column:1/-1}
  .feed ul{list-style:none;margin:0;padding:0;max-height:260px;overflow:auto;
           font:13px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace}
  .feed li{display:flex;gap:12px;padding:4px 0;border-top:1px solid var(--line)}
  .feed .t{color:var(--mut);flex:0 0 86px}
  .feed .kind{color:var(--accent);flex:0 0 120px;font-weight:600}
  .note{grid-column:1/-1;color:var(--mut);font-size:12px;text-align:center;padding-top:4px}
</style>
</head>
<body>
<header>
  <div class="logo"></div>
  <div>
    <h1>Chakravyuh</h1>
    <div class="sub">Sealed adversarial-AI testing arena · metadata-only view</div>
  </div>
  <div class="phase" id="phase">—</div>
</header>
<main>
  <div class="card">
    <h2>Canary Leakage Score</h2>
    <div class="big" id="leaks">—</div>
    <div class="sub" id="leaksub">no probe run yet · target = 0</div>
  </div>
  <div class="card">
    <h2>Test</h2>
    <div class="row"><span class="k">Test ID</span><span class="v" id="tid">—</span></div>
    <div class="row"><span class="k">Model session</span><span class="v" id="sess">—</span></div>
    <div class="row"><span class="k">Committed payloads</span><span class="v" id="ncommit">—</span></div>
    <div class="row"><span class="k">Reveal verified</span><span class="v" id="rev">—</span></div>
  </div>
  <div class="card">
    <h2>Verdicts</h2>
    <div class="row"><span class="k">Attacks processed</span><span class="v" id="natk">0</span></div>
    <div class="row"><span class="k">Blocked</span><span class="v" id="blk">0</span></div>
    <div class="row"><span class="k">Allowed</span><span class="v" id="alw">0</span></div>
  </div>
  <div class="card">
    <h2>Timing Defense</h2>
    <div class="row"><span class="k">Latency quantum</span><span class="v" id="q">—</span></div>
    <div class="row"><span class="k">Avg pad applied</span><span class="v" id="pad">—</span></div>
    <div class="row"><span class="k">Padded responses</span><span class="v" id="padn">0</span></div>
  </div>
  <div class="card" style="grid-column:1/-1">
    <h2>Lanes (network-isolated, broker-bridged)</h2>
    <div class="lanes">
      <div class="lane"><div class="nm">RED</div><div class="st">sealed · commit-reveal</div></div>
      <div class="lane"><div class="nm">BROKER</div><div class="st">default-deny policy</div></div>
      <div class="lane"><div class="nm">MODEL</div><div class="st">ephemeral session</div></div>
      <div class="lane"><div class="nm">BLUE</div><div class="st">sealed · verdict only</div></div>
    </div>
  </div>
  <div class="card feed">
    <h2>Audit Event Feed (metadata only — no payloads)</h2>
    <ul id="feed"></ul>
  </div>
  <div class="note">Polling /state and /events every 1.5 s. Payload content and model output never cross this layer.</div>
</main>
<script>
const $=id=>document.getElementById(id);
async function tick(){
  try{
    const s=await (await fetch('/state')).json();
    const e=await (await fetch('/events')).json();
    $('phase').textContent=(s.phase||'—').toUpperCase();
    $('tid').textContent=s.test_id||'—';
    $('sess').textContent=s.model_session||'—';
    $('ncommit').textContent=s.n_committed_payloads||'—';
    $('rev').innerHTML=s.payloads_revealed?'<span class="pill ok">verified</span>':'<span class="pill bad">pending</span>';
    $('natk').textContent=s.attacks_processed||0;
    $('blk').textContent=(s.verdicts&&s.verdicts.blocked)||0;
    $('alw').textContent=(s.verdicts&&s.verdicts.allowed)||0;
    const cr=s.canary_report;
    if(cr){
      $('leaks').textContent=cr.leaks_found;
      $('leaks').style.color=cr.leaks_found===0?'var(--ok)':'var(--bad)';
      $('leaksub').textContent=cr.probes_run+' probes · target = 0';
    }
    const p=e.padding||{};
    $('q').textContent=(p.quantum_ms??'—')+' ms';
    $('pad').textContent=(p.avg_pad_ms??'—')+' ms';
    $('padn').textContent=p.requests||0;
    const feed=$('feed'); feed.innerHTML='';
    (e.events||[]).slice().reverse().forEach(ev=>{
      const li=document.createElement('li');
      const d=new Date(ev.ts*1000).toLocaleTimeString();
      const extra=Object.entries(ev).filter(([k])=>!['ts','kind'].includes(k))
                   .map(([k,v])=>k+'='+v).join(' ');
      li.innerHTML=`<span class="t">${d}</span><span class="kind">${ev.kind}</span><span>${extra}</span>`;
      feed.appendChild(li);
    });
  }catch(err){/* broker warming up */}
}
tick(); setInterval(tick,1500);
</script>
</body>
</html>
"""
