import { useState, useEffect, useCallback } from "react";

// ─── AUTH ─────────────────────────────────────────────────────────────────────
const AUTH_USER = import.meta.env.VITE_DASHBOARD_USER || "analyst";
const AUTH_PASS = import.meta.env.VITE_DASHBOARD_PASS || "kpmg2024";

const LoginPage = ({ onLogin }) => {
  const [user, setUser]   = useState("");
  const [pass, setPass]   = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    await new Promise(r => setTimeout(r, 600)); // slight delay feels more real
    if (user === AUTH_USER && pass === AUTH_PASS) {
      sessionStorage.setItem("soc_auth", "1");
      onLogin();
    } else {
      setError("Invalid credentials");
      setLoading(false);
    }
  };

  return (
    <div style={{ width:"100vw", height:"100vh", background:"#0a0a0f", display:"flex", alignItems:"center", justifyContent:"center", fontFamily:"'Inter',sans-serif" }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;500;600;700;800&display=swap'); *{box-sizing:border-box;margin:0;padding:0} @keyframes spin{to{transform:rotate(360deg)}}`}</style>

      {/* Background grid */}
      <div style={{ position:"fixed", inset:0, backgroundImage:"linear-gradient(rgba(59,130,246,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(59,130,246,0.03) 1px,transparent 1px)", backgroundSize:"40px 40px", pointerEvents:"none" }}/>

      <div style={{ position:"relative", width:380, padding:"40px 36px", background:"#0d0d15", border:"1px solid rgba(255,255,255,0.08)", borderRadius:8, boxShadow:"0 32px 80px rgba(0,0,0,0.6)" }}>
        {/* Logo */}
        <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:32 }}>
          <div style={{ width:36, height:36, background:"linear-gradient(135deg,#3b82f6,#1e40af)", borderRadius:6, display:"flex", alignItems:"center", justifyContent:"center", fontSize:18 }}>⬡</div>
          <div>
            <div style={{ fontSize:14, fontWeight:800, letterSpacing:"0.06em", color:"#fff" }}>KPMG MDR</div>
            <div style={{ fontSize:10, color:"rgba(255,255,255,0.3)", letterSpacing:"0.14em" }}>SOC ALERT TRIAGE COPILOT</div>
          </div>
        </div>

        <div style={{ fontSize:18, fontWeight:700, color:"rgba(255,255,255,0.9)", marginBottom:6 }}>Analyst Sign In</div>
        <div style={{ fontSize:12, color:"rgba(255,255,255,0.35)", marginBottom:28 }}>Restricted access — authorised personnel only</div>

        <form onSubmit={submit}>
          <div style={{ marginBottom:16 }}>
            <label style={{ display:"block", fontSize:11, fontWeight:600, color:"rgba(255,255,255,0.4)", letterSpacing:"0.08em", marginBottom:7 }}>USERNAME</label>
            <input value={user} onChange={e => { setUser(e.target.value); setError(""); }}
              autoFocus autoComplete="username"
              style={{ width:"100%", padding:"11px 14px", background:"rgba(255,255,255,0.04)", border:`1px solid ${error?"rgba(239,68,68,0.5)":"rgba(255,255,255,0.1)"}`, borderRadius:4, color:"#fff", fontSize:13, fontFamily:"'Inter',sans-serif", outline:"none" }}
            />
          </div>
          <div style={{ marginBottom:24 }}>
            <label style={{ display:"block", fontSize:11, fontWeight:600, color:"rgba(255,255,255,0.4)", letterSpacing:"0.08em", marginBottom:7 }}>PASSWORD</label>
            <input type="password" value={pass} onChange={e => { setPass(e.target.value); setError(""); }}
              autoComplete="current-password"
              style={{ width:"100%", padding:"11px 14px", background:"rgba(255,255,255,0.04)", border:`1px solid ${error?"rgba(239,68,68,0.5)":"rgba(255,255,255,0.1)"}`, borderRadius:4, color:"#fff", fontSize:13, fontFamily:"'Inter',sans-serif", outline:"none" }}
            />
          </div>
          {error && <div style={{ marginBottom:16, fontSize:12, color:"#ef4444", display:"flex", alignItems:"center", gap:6 }}>⚠ {error}</div>}
          <button type="submit" disabled={loading} style={{ width:"100%", padding:"12px 0", background:loading?"rgba(59,130,246,0.4)":"#3b82f6", border:"none", borderRadius:4, color:"#fff", fontSize:13, fontWeight:700, cursor:loading?"default":"pointer", display:"flex", alignItems:"center", justifyContent:"center", gap:8, transition:"background .2s" }}>
            {loading ? <><div style={{ width:14, height:14, border:"2px solid rgba(255,255,255,0.3)", borderTopColor:"#fff", borderRadius:"50%", animation:"spin .7s linear infinite" }}/> Authenticating…</> : "Sign In →"}
          </button>
        </form>

        <div style={{ marginTop:24, paddingTop:20, borderTop:"1px solid rgba(255,255,255,0.06)", fontSize:10, color:"rgba(255,255,255,0.2)", textAlign:"center", letterSpacing:"0.04em" }}>
          KPMG MANAGED DETECTION & RESPONSE · CONFIDENTIAL
        </div>
      </div>
    </div>
  );
};

// ─── API ──────────────────────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "/backend";

const api = {
  getAlerts:  ()    => fetch(`${API_BASE}/alerts`).then(r => r.json()),
  getAlert:   (id)  => fetch(`${API_BASE}/alerts/${id}`).then(r => r.json()),
  getMetrics: ()    => fetch(`${API_BASE}/metrics`).then(r => r.json()),
  escalate:   (id)  => fetch(`${API_BASE}/alerts/${id}/escalate`, { method:"POST", headers:{"Content-Type":"application/json"}, body:"{}" }).then(r => r.json()),
  dismiss:    (id)  => fetch(`${API_BASE}/alerts/${id}/dismiss`, { method:"POST" }).then(r => r.json()),
};

// ─── CONFIG ────────────────────────────────────────────────────────────────────
const SEV = {
  Critical: { color:"#ef4444", bg:"rgba(239,68,68,0.1)",  border:"rgba(239,68,68,0.28)" },
  High:     { color:"#f97316", bg:"rgba(249,115,22,0.1)", border:"rgba(249,115,22,0.28)" },
  Medium:   { color:"#eab308", bg:"rgba(234,179,8,0.1)",  border:"rgba(234,179,8,0.28)" },
  Low:      { color:"#3b82f6", bg:"rgba(59,130,246,0.1)", border:"rgba(59,130,246,0.28)" },
};
const CLS = {
  "True Positive":  { color:"#ef4444", bg:"rgba(239,68,68,0.08)",  short:"TP" },
  "False Positive": { color:"#22c55e", bg:"rgba(34,197,94,0.08)",  short:"FP" },
  "Needs Review":   { color:"#eab308", bg:"rgba(234,179,8,0.08)",  short:"NR" },
};
const LEVEL_COLOR = l => ["","#6b7280","#3b82f6","#eab308","#f97316","#ef4444"][l] || "#6b7280";
const relTime = d => { const m=Math.floor((Date.now()-new Date(d))/60000); if(m<1)return"just now"; if(m<60)return`${m}m ago`; const h=Math.floor(m/60); if(h<24)return`${h}h ago`; return`${Math.floor(h/24)}d ago`; };
const utcStr  = d => new Date(d).toISOString().replace("T"," ").slice(0,19)+" UTC";

// ─── ATOMS ─────────────────────────────────────────────────────────────────────
const Badge = ({ children, color, bg, border }) => (
  <span style={{ padding:"2px 9px", borderRadius:2, fontSize:10, fontWeight:700, letterSpacing:"0.04em", color, background:bg, border:`1px solid ${border||"transparent"}` }}>{children}</span>
);
const SectionLabel = ({ children }) => (
  <div style={{ fontSize:10, fontWeight:600, color:"rgba(255,255,255,0.28)", letterSpacing:"0.1em", marginBottom:8 }}>{children}</div>
);
const Spinner = ({ size=10, color="#ef4444" }) => (
  <div style={{ width:size, height:size, border:`2px solid ${color}44`, borderTopColor:color, borderRadius:"50%", animation:"spin .7s linear infinite", flexShrink:0 }}/>
);

// ─── KQL BLOCK ─────────────────────────────────────────────────────────────────
const KQLBlock = ({ kql }) => {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(kql).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div style={{ background:"rgba(0,0,0,0.5)", border:"1px solid rgba(59,130,246,0.25)", borderRadius:4, overflow:"hidden" }}>
      {/* Header bar */}
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"8px 14px", background:"rgba(59,130,246,0.08)", borderBottom:"1px solid rgba(59,130,246,0.15)" }}>
        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
          <span style={{ fontSize:9, fontWeight:700, color:"#3b82f6", letterSpacing:"0.1em" }}>KQL · SENTINEL QUERY</span>
          <span style={{ fontSize:9, color:"rgba(255,255,255,0.3)" }}>— paste directly into Log Analytics query editor</span>
        </div>
        <button onClick={copy} style={{
          padding:"4px 12px", borderRadius:3, fontSize:10, fontWeight:600, cursor:"pointer",
          border:`1px solid ${copied?"rgba(34,197,94,0.4)":"rgba(59,130,246,0.35)"}`,
          background:copied?"rgba(34,197,94,0.1)":"rgba(59,130,246,0.1)",
          color:copied?"#22c55e":"#3b82f6", transition:"all .2s",
          display:"flex", alignItems:"center", gap:5,
        }}>
          {copied ? <>✓ Copied!</> : <>⎘ Copy Query</>}
        </button>
      </div>
      {/* Query text */}
      <pre style={{
        fontFamily:"'JetBrains Mono',monospace", fontSize:11, lineHeight:1.8,
        color:"rgba(255,255,255,0.75)", padding:"14px 16px",
        overflowX:"auto", whiteSpace:"pre", margin:0,
      }}>
        {kql.split("\\n").map((line, i) => {
          // Syntax highlight KQL keywords
          const highlighted = line
            .replace(/\b(where|project|order by|summarize|extend|join|let|union|count|distinct|ago|between|datetime|now|asc|desc|by|kind|on|limit|take|top|render)\b/g, '<kw>$1</kw>')
            .replace(/\b(TimeGenerated|EventID_d|AccountName_s|IpAddress_s|WorkstationName_s|SourceHost_s|DestinationIp_s|EventType_s|LogonType_d|NewProcessName_s|CommandLine_s)\b/g, '<field>$1</field>')
            .replace(/(".*?")/g, '<str>$1</str>')
            .replace(/(SOCCopilotLogs_CL)/g, '<table>$1</table>')
            .replace(/(\|)/g, '<pipe>$1</pipe>');

          return (
            <span key={i} dangerouslySetInnerHTML={{ __html:
              highlighted
                .replace(/<kw>(.*?)<\/kw>/g, '<span style="color:#c084fc;font-weight:600">$1</span>')
                .replace(/<field>(.*?)<\/field>/g, '<span style="color:#38bdf8">$1</span>')
                .replace(/<str>(.*?)<\/str>/g, '<span style="color:#86efac">$1</span>')
                .replace(/<table>(.*?)<\/table>/g, '<span style="color:#fb923c;font-weight:600">$1</span>')
                .replace(/<pipe>(.*?)<\/pipe>/g, '<span style="color:#94a3b8">$1</span>')
              + "\n"
            }}/>
          );
        })}
      </pre>
    </div>
  );
};

// ─── CONFIDENCE ARC ────────────────────────────────────────────────────────────
const ConfArc = ({ value }) => {
  const [v, setV] = useState(0);
  useEffect(() => { const t = setTimeout(() => setV(value), 200); return () => clearTimeout(t); }, [value]);
  const R=34, C=2*Math.PI*R, off=C-(v/100)*C;
  const col = v>=85?"#ef4444":v>=65?"#f97316":"#eab308";
  return (
    <div style={{ position:"relative", width:80, height:80, flexShrink:0 }}>
      <svg width="80" height="80" style={{ transform:"rotate(-90deg)" }}>
        <circle cx="40" cy="40" r={R} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="5"/>
        <circle cx="40" cy="40" r={R} fill="none" stroke={col} strokeWidth="5"
          strokeDasharray={C} strokeDashoffset={off} strokeLinecap="round"
          style={{ transition:"stroke-dashoffset 1s cubic-bezier(.4,0,.2,1)" }}/>
      </svg>
      <div style={{ position:"absolute", inset:0, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center" }}>
        <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:16, fontWeight:700, color:col, lineHeight:1 }}>{v}%</div>
        <div style={{ fontSize:8, color:"rgba(255,255,255,0.3)", marginTop:1 }}>CONF</div>
      </div>
    </div>
  );
};

const MitreTag = ({ id, name }) => (
  <span style={{ display:"inline-flex", alignItems:"center", gap:5, padding:"3px 9px", background:"rgba(59,130,246,0.07)", border:"1px solid rgba(59,130,246,0.18)", borderRadius:2, fontSize:10, fontFamily:"'JetBrains Mono',monospace", whiteSpace:"nowrap" }}>
    <span style={{ color:"#3b82f6" }}>{id}</span>
    <span style={{ color:"rgba(255,255,255,0.5)" }}>{name}</span>
  </span>
);

// ─── ATTACK TIMELINE ───────────────────────────────────────────────────────────
const Timeline = ({ events, pivotalId, pivotalKql }) => {
  const [open, setOpen] = useState(null);
  if (!events || events.length === 0) return <div style={{ color:"rgba(255,255,255,0.3)", fontSize:12 }}>No timeline events available.</div>;

  return (
    <div style={{ position:"relative", paddingLeft:28 }}>
      <div style={{ position:"absolute", left:9, top:16, bottom:16, width:2, background:"linear-gradient(to bottom,rgba(59,130,246,0.5),rgba(59,130,246,0.05))" }}/>
      {events.map(ev => {
        const isPivot = ev.id === pivotalId || ev.is_pivot_point;
        const dc = LEVEL_COLOR(ev.severity_level || 3);
        const isOpen = open === ev.id;
        return (
          <div key={ev.id} style={{ position:"relative", marginBottom:isPivot?8:16 }}>
            <div style={{ position:"absolute", left:-28, top:isPivot?6:11,
              width:isPivot?20:12, height:isPivot?20:12, borderRadius:"50%", background:dc,
              boxShadow:isPivot?`0 0 0 4px rgba(239,68,68,0.15),0 0 20px ${dc}88`:"none",
              transform:isPivot?"translateX(-4px)":"none", zIndex:2 }}/>
            <div onClick={() => setOpen(isOpen ? null : ev.id)}
              style={{ background:isPivot?"rgba(239,68,68,0.05)":"rgba(255,255,255,0.015)", border:`1px solid ${isPivot?"rgba(239,68,68,0.2)":"rgba(255,255,255,0.06)"}`, borderRadius:3, padding:"11px 13px", cursor:"pointer", transition:"background .15s" }}
              onMouseEnter={e => e.currentTarget.style.background = isPivot?"rgba(239,68,68,0.08)":"rgba(255,255,255,0.03)"}
              onMouseLeave={e => e.currentTarget.style.background = isPivot?"rgba(239,68,68,0.05)":"rgba(255,255,255,0.015)"}
            >
              {isPivot && <div style={{ display:"inline-flex", alignItems:"center", gap:4, marginBottom:5, padding:"1px 7px", background:"rgba(239,68,68,0.12)", border:"1px solid rgba(239,68,68,0.35)", borderRadius:2, fontSize:9, fontWeight:800, letterSpacing:"0.1em", color:"#ef4444" }}>⚡ PIVOTAL EVENT</div>}
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", gap:10 }}>
                <div style={{ flex:1 }}>
                  <div style={{ fontSize:12, fontWeight:600, color:"rgba(255,255,255,0.88)", marginBottom:3 }}>{ev.event_type}</div>
                  <div style={{ fontSize:11, color:"rgba(255,255,255,0.5)", lineHeight:1.5 }}>{ev.description}</div>
                </div>
                <div style={{ textAlign:"right", flexShrink:0 }}>
                  <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:"rgba(255,255,255,0.3)" }}>{utcStr(ev.timestamp)}</div>
                  <div style={{ fontSize:9, color:"#3b82f6", marginTop:3 }}>{ev.mitre_tactic}</div>
                </div>
              </div>
              {isOpen && ev.raw_log && (
                <div style={{ marginTop:10, paddingTop:10, borderTop:"1px solid rgba(255,255,255,0.05)" }}>
                  <div style={{ fontSize:9, color:"#3b82f6", fontFamily:"'JetBrains Mono',monospace", marginBottom:6 }}>▸ RAW LOG</div>
                  <pre style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:"rgba(255,255,255,0.55)", background:"rgba(0,0,0,0.5)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:2, padding:"10px 12px", overflowX:"auto", whiteSpace:"pre-wrap", wordBreak:"break-all", margin:0, lineHeight:1.7 }}>
                    {typeof ev.raw_log === "string" ? (() => { try { return JSON.stringify(JSON.parse(ev.raw_log),null,2); } catch { return ev.raw_log; } })() : JSON.stringify(ev.raw_log, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            {/* KQL block directly below the pivotal event card */}
            {isPivot && pivotalKql && (
              <div style={{ marginTop:8, marginBottom:16 }}>
                <div style={{ fontSize:9, color:"rgba(255,255,255,0.28)", letterSpacing:"0.1em", marginBottom:6, paddingLeft:2 }}>SENTINEL JUMP QUERY — copy and run in Log Analytics to find this exact event</div>
                <KQLBlock kql={pivotalKql}/>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

// ─── FULL-SCREEN MODAL ─────────────────────────────────────────────────────────
const AlertModal = ({ alertSummary, onClose, onEscalate, onDismiss }) => {
  const [full, setFull]             = useState(null);
  const [loading, setLoading]       = useState(true);
  const [escalating, setEscalating] = useState(false);
  const [escalated,  setEscalated]  = useState(alertSummary.status === "Escalated");

  useEffect(() => {
    api.getAlert(alertSummary.id).then(data => { setFull(data); setLoading(false); });
  }, [alertSummary.id]);

  useEffect(() => {
    const h = e => { if(e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  const alert = full || alertSummary;
  const sev = SEV[alert.severity] || SEV.Medium;
  const cls = CLS[alert.classification] || CLS["Needs Review"];

  const doEscalate = async () => {
    setEscalating(true);
    await api.escalate(alert.id);
    setEscalating(false);
    setEscalated(true);
    onEscalate(alert.id);
  };

  return (
    <div style={{ position:"fixed", inset:0, zIndex:200, display:"flex", alignItems:"center", justifyContent:"center" }}
      onClick={e => { if(e.target === e.currentTarget) onClose(); }}>
      <div style={{ position:"absolute", inset:0, background:"rgba(0,0,0,0.82)", backdropFilter:"blur(5px)" }}/>
      <div style={{
        position:"relative", width:"min(920px,96vw)", maxHeight:"90vh",
        background:"#0d0d15", border:"1px solid rgba(255,255,255,0.09)", borderRadius:6,
        display:"flex", flexDirection:"column",
        animation:"modalIn .28s cubic-bezier(.4,0,.2,1)",
        boxShadow:"0 40px 100px rgba(0,0,0,0.8)", overflow:"hidden",
      }}>
        <div style={{ height:2, background:`linear-gradient(90deg,${sev.color},${sev.color}55,transparent)`, flexShrink:0 }}/>

        {/* Header */}
        <div style={{ padding:"20px 26px 16px", borderBottom:"1px solid rgba(255,255,255,0.06)", flexShrink:0 }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", gap:16 }}>
            <div style={{ flex:1 }}>
              <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:9, flexWrap:"wrap" }}>
                <Badge color={sev.color} bg={sev.bg} border={sev.border}>{alert.severity?.toUpperCase()}</Badge>
                <Badge color={cls.color} bg={cls.bg}>{alert.classification}</Badge>
                <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:10, color:"rgba(255,255,255,0.22)" }}>{alert.id}</span>
              </div>
              <div style={{ fontSize:19, fontWeight:700, color:"rgba(255,255,255,0.95)", lineHeight:1.3, marginBottom:9 }}>{alert.title}</div>
              <div style={{ display:"flex", alignItems:"center", gap:16, flexWrap:"wrap" }}>
                <span style={{ fontSize:11, color:"rgba(255,255,255,0.35)", fontFamily:"'JetBrains Mono',monospace" }}>⬡ {alert.source_host}</span>
                <span style={{ fontSize:11, color:"rgba(255,255,255,0.35)", fontFamily:"'JetBrains Mono',monospace" }}>{alert.source_ip}</span>
                {alert.external_ip && <span style={{ fontSize:11, color:"#ef4444", fontFamily:"'JetBrains Mono',monospace" }}>→ {alert.external_ip}</span>}
                <span style={{ fontSize:11, color:"rgba(255,255,255,0.2)", fontFamily:"'JetBrains Mono',monospace" }}>{alert.created_at ? utcStr(alert.created_at) : ""}</span>
              </div>
            </div>
            <div style={{ display:"flex", alignItems:"flex-start", gap:12, flexShrink:0 }}>
              {alert.confidence && <ConfArc value={alert.confidence}/>}
              <button onClick={onClose} style={{ background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.09)", borderRadius:3, padding:"7px 10px", cursor:"pointer", color:"rgba(255,255,255,0.45)", fontSize:14, lineHeight:1 }}>✕</button>
            </div>
          </div>
          {alert.mitre_tactics?.length > 0 && (
            <div style={{ display:"flex", flexWrap:"wrap", gap:6, marginTop:12 }}>
              {alert.mitre_tactics.map(t => <MitreTag key={t.id} id={t.id} name={t.name}/>)}
            </div>
          )}
        </div>

        {/* Body */}
        <div style={{ flex:1, overflowY:"auto", padding:"20px 26px", display:"flex", flexDirection:"column", gap:20 }}>
          {loading ? (
            <div style={{ display:"flex", alignItems:"center", gap:10, color:"rgba(255,255,255,0.4)", fontSize:12 }}>
              <Spinner color="#3b82f6" size={14}/> Loading full triage from Claude AI…
            </div>
          ) : (
            <>
              <div>
                <SectionLabel>AI TRIAGE SUMMARY</SectionLabel>
                <div style={{ fontSize:12, color:"rgba(255,255,255,0.68)", lineHeight:1.85, padding:"13px 16px", background:"rgba(59,130,246,0.04)", border:"1px solid rgba(59,130,246,0.1)", borderRadius:3 }}>
                  {alert.triage_summary}
                </div>
              </div>
              {alert.attack_story && (
                <div>
                  <SectionLabel>ATTACK NARRATIVE</SectionLabel>
                  <div style={{ fontSize:12, color:"rgba(255,255,255,0.52)", lineHeight:1.9, fontStyle:"italic", padding:"13px 16px", background:"rgba(255,255,255,0.015)", border:"1px solid rgba(255,255,255,0.055)", borderRadius:3 }}>
                    {alert.attack_story}
                  </div>
                </div>
              )}
              <div>
                <SectionLabel>ATTACK TIMELINE — {alert.timeline?.length || 0} EVENTS · CLICK TO EXPAND RAW LOG</SectionLabel>
                <Timeline events={alert.timeline || []} pivotalId={alert.pivotal_event} pivotalKql={alert.pivotal_kql}/>
              </div>
              {alert.recommended_action && (
                <div>
                  <SectionLabel>RECOMMENDED ACTIONS</SectionLabel>
                  <div style={{ fontSize:12, color:"rgba(255,255,255,0.62)", lineHeight:1.85, whiteSpace:"pre-line", padding:"13px 16px", background:"rgba(255,255,255,0.015)", border:"1px solid rgba(255,255,255,0.055)", borderRadius:3 }}>
                    {alert.recommended_action}
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div style={{ padding:"14px 26px", borderTop:"1px solid rgba(255,255,255,0.06)", display:"flex", gap:10, flexShrink:0, background:"rgba(0,0,0,0.25)" }}>
          {alert.classification !== "False Positive" && (
            <button onClick={doEscalate} disabled={escalating||escalated} style={{
              flex:1, padding:"11px 0", borderRadius:3, fontSize:12, fontWeight:700, cursor:escalated?"default":"pointer",
              border:`1px solid ${escalated?"rgba(34,197,94,0.4)":"rgba(239,68,68,0.45)"}`,
              background:escalated?"rgba(34,197,94,0.08)":escalating?"rgba(239,68,68,0.04)":"rgba(239,68,68,0.1)",
              color:escalated?"#22c55e":"#ef4444",
              display:"flex", alignItems:"center", justifyContent:"center", gap:7, transition:"all .25s",
            }}>
              {escalating?<><Spinner/>Posting to Slack…</>:escalated?<>✓ Escalated to L2 via Slack</>:<>↑ Escalate to L2</>}
            </button>
          )}
          <button onClick={async () => { await api.dismiss(alert.id); onDismiss(alert.id); onClose(); }}
            style={{ flex:1, padding:"11px 0", borderRadius:3, fontSize:12, fontWeight:600, cursor:"pointer", border:"1px solid rgba(255,255,255,0.09)", background:"rgba(255,255,255,0.03)", color:"rgba(255,255,255,0.45)", transition:"all .15s" }}
            onMouseEnter={e=>{e.currentTarget.style.background="rgba(255,255,255,0.07)";e.currentTarget.style.color="rgba(255,255,255,0.8)";}}
            onMouseLeave={e=>{e.currentTarget.style.background="rgba(255,255,255,0.03)";e.currentTarget.style.color="rgba(255,255,255,0.45)";}}>
            Mark False Positive
          </button>
          <button onClick={onClose} style={{ padding:"11px 18px", borderRadius:3, fontSize:12, border:"1px solid rgba(255,255,255,0.07)", background:"transparent", color:"rgba(255,255,255,0.32)", cursor:"pointer" }}>
            Close <span style={{ fontSize:10, color:"rgba(255,255,255,0.2)" }}>ESC</span>
          </button>
        </div>
      </div>
    </div>
  );
};

// ─── ALERT CARD ────────────────────────────────────────────────────────────────
const AlertCard = ({ alert, onClick, isNew }) => {
  const sev = SEV[alert.severity] || SEV.Low;
  const cls = CLS[alert.classification] || CLS["Needs Review"];
  return (
    <div onClick={onClick} style={{
      borderLeft:`3px solid ${sev.color}`,
      background:isNew?"rgba(59,130,246,0.025)":"rgba(255,255,255,0.015)",
      border:`1px solid ${isNew?"rgba(59,130,246,0.18)":"rgba(255,255,255,0.055)"}`,
      borderLeftWidth:3, borderLeftColor:sev.color, borderLeftStyle:"solid",
      borderRadius:3, padding:"11px 14px", cursor:"pointer", marginBottom:5,
      transition:"all .15s", position:"relative", overflow:"hidden",
      animation:isNew?"cardIn .4s ease":"none",
    }}
      onMouseEnter={e=>e.currentTarget.style.background="rgba(255,255,255,0.035)"}
      onMouseLeave={e=>e.currentTarget.style.background=isNew?"rgba(59,130,246,0.025)":"rgba(255,255,255,0.015)"}
    >
      {isNew&&<div style={{ position:"absolute", top:0, left:0, right:0, height:1, background:"linear-gradient(90deg,transparent,rgba(59,130,246,0.5),transparent)", animation:"shimmer 2.5s ease infinite" }}/>}
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", gap:12 }}>
        <div style={{ flex:1, minWidth:0 }}>
          <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:5, flexWrap:"wrap" }}>
            <Badge color={sev.color} bg={sev.bg} border={sev.border}>{alert.severity?.toUpperCase()}</Badge>
            <Badge color={cls.color} bg={cls.bg}>{cls.short}</Badge>
            {alert.status==="New"       && <Badge color="#3b82f6" bg="rgba(59,130,246,0.08)">NEW</Badge>}
            {alert.status==="Escalated" && <Badge color="#ef4444" bg="rgba(239,68,68,0.08)">ESCALATED</Badge>}
            {alert.status==="Dismissed" && <Badge color="#6b7280" bg="rgba(107,114,128,0.08)">DISMISSED</Badge>}
            {alert.status==="In Review" && <Badge color="#a78bfa" bg="rgba(167,139,250,0.08)">IN REVIEW</Badge>}
          </div>
          <div style={{ fontSize:12, fontWeight:600, color:"rgba(255,255,255,0.88)", marginBottom:5, lineHeight:1.3 }}>{alert.title}</div>
          <div style={{ display:"flex", gap:12 }}>
            <span style={{ fontSize:10, color:"rgba(255,255,255,0.32)", fontFamily:"'JetBrains Mono',monospace" }}>⬡ {alert.source_host}</span>
            <span style={{ fontSize:10, color:"rgba(255,255,255,0.32)", fontFamily:"'JetBrains Mono',monospace" }}>{alert.source_ip}</span>
          </div>
        </div>
        <div style={{ textAlign:"right", flexShrink:0 }}>
          <div style={{ fontSize:10, color:"rgba(255,255,255,0.28)", fontFamily:"'JetBrains Mono',monospace", marginBottom:6 }}>{alert.created_at?relTime(alert.created_at):""}</div>
          <div style={{ fontSize:9, color:"rgba(255,255,255,0.28)", marginBottom:3 }}>{alert.confidence}% conf</div>
          <div style={{ width:72, height:2, background:"rgba(255,255,255,0.07)", borderRadius:1 }}>
            <div style={{ width:`${alert.confidence||0}%`, height:"100%", borderRadius:1, background:cls.color, opacity:.7 }}/>
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── METRICS PANEL ─────────────────────────────────────────────────────────────
const MetricsPanel = ({ metrics, loading }) => {
  if (loading) return <div style={{ color:"rgba(255,255,255,0.3)", fontSize:12, display:"flex", alignItems:"center", gap:8 }}><Spinner color="#3b82f6" size={12}/>Loading…</div>;
  if (!metrics) return null;
  const { total=0, true_positive:tp=0, false_positive:fp=0, needs_review:nr=0, hourly_volume=[], top_mitre_tactics=[] } = metrics;
  const maxV = Math.max(...hourly_volume.map(d=>d.count), 1);
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8 }}>
        {[{l:"TOTAL ALERTS",v:total,c:"rgba(255,255,255,0.85)"},{l:"TRUE POSITIVES",v:tp,c:"#ef4444"},{l:"FALSE POSITIVES",v:fp,c:"#22c55e"},{l:"NEEDS REVIEW",v:nr,c:"#eab308"}].map(({l,v,c})=>(
          <div key={l} style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:3, padding:"12px 14px" }}>
            <div style={{ fontSize:9, color:"rgba(255,255,255,0.28)", letterSpacing:"0.1em", marginBottom:6 }}>{l}</div>
            <div style={{ fontSize:26, fontWeight:800, color:c, fontFamily:"'JetBrains Mono',monospace", lineHeight:1 }}>{v}</div>
          </div>
        ))}
      </div>
      {total>0&&<div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:3, padding:"12px 14px" }}>
        <SectionLabel>CLASSIFICATION SPLIT</SectionLabel>
        <div style={{ display:"flex", height:18, borderRadius:2, overflow:"hidden", gap:1 }}>
          {[{v:tp,c:"#ef4444",l:"TP"},{v:nr,c:"#eab308",l:"NR"},{v:fp,c:"#22c55e",l:"FP"}].map(({v,c,l})=>v>0&&(
            <div key={l} style={{ flex:v, background:c, opacity:.6, display:"flex", alignItems:"center", justifyContent:"center", fontSize:9, fontWeight:800, color:"rgba(0,0,0,0.7)" }}>{v}</div>
          ))}
        </div>
      </div>}
      {top_mitre_tactics.length>0&&<div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:3, padding:"12px 14px" }}>
        <SectionLabel>TOP MITRE TACTICS</SectionLabel>
        {top_mitre_tactics.map(({name,count},i)=>(
          <div key={name} style={{ display:"flex", alignItems:"center", gap:8, marginBottom:7 }}>
            <div style={{ width:16, height:16, background:"rgba(59,130,246,0.1)", border:"1px solid rgba(59,130,246,0.2)", borderRadius:2, display:"flex", alignItems:"center", justifyContent:"center", fontSize:8, color:"#3b82f6", fontWeight:700 }}>{i+1}</div>
            <div style={{ flex:1, fontSize:10, color:"rgba(255,255,255,0.5)", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{name}</div>
            <div style={{ fontSize:11, fontWeight:700, color:"#3b82f6", fontFamily:"'JetBrains Mono',monospace" }}>{count}</div>
          </div>
        ))}
      </div>}
      {hourly_volume.length>0&&<div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:3, padding:"12px 14px" }}>
        <SectionLabel>ALERT VOLUME — HOURLY</SectionLabel>
        <div style={{ display:"flex", alignItems:"flex-end", gap:3, height:44 }}>
          {hourly_volume.map(({hour,count})=>(
            <div key={hour} style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center", gap:3 }}>
              <div style={{ width:"100%", background:"rgba(59,130,246,0.4)", borderRadius:"2px 2px 0 0", height:`${(count/maxV)*36}px`, minHeight:3 }}/>
              <div style={{ fontSize:7, color:"rgba(255,255,255,0.2)", fontFamily:"'JetBrains Mono',monospace" }}>{new Date(hour).getHours().toString().padStart(2,"0")}</div>
            </div>
          ))}
        </div>
      </div>}
      <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.06)", borderRadius:3, padding:"12px 14px" }}>
        <SectionLabel>AVG CONFIDENCE</SectionLabel>
        <div style={{ fontSize:28, fontWeight:800, color:"#3b82f6", fontFamily:"'JetBrains Mono',monospace" }}>{metrics.avg_confidence||0}%</div>
      </div>
    </div>
  );
};

// ─── MAIN APP ──────────────────────────────────────────────────────────────────
export default function App() {
  const [authed,  setAuthed]  = useState(!!sessionStorage.getItem("soc_auth"));
  const [alerts,  setAlerts]  = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [modal,   setModal]   = useState(null);
  const [sevFilter, setSevFilter] = useState("All");
  const [clsFilter, setClsFilter] = useState("All");
  const [time,    setTime]    = useState(new Date());
  const [alertsLoading,  setAlertsLoading]  = useState(true);
  const [metricsLoading, setMetricsLoading] = useState(true);
  const [backendOk, setBackendOk] = useState(null);
  const [newIds,  setNewIds]  = useState(new Set());

  useEffect(() => { const t = setInterval(() => setTime(new Date()), 1000); return () => clearInterval(t); }, []);

  const fetchAlerts = useCallback(async () => {
    try {
      const data = await api.getAlerts();
      const incoming = data.alerts || [];
      setAlerts(prev => {
        const prevIds = new Set(prev.map(a => a.id));
        const brand = incoming.filter(a => !prevIds.has(a.id)).map(a => a.id);
        if (brand.length > 0) {
          setNewIds(ids => { const n = new Set(ids); brand.forEach(id => n.add(id)); return n; });
          setTimeout(() => setNewIds(ids => { const n = new Set(ids); brand.forEach(id => n.delete(id)); return n; }), 8000);
        }
        return incoming;
      });
      setAlertsLoading(false);
      setBackendOk(true);
    } catch { setBackendOk(false); setAlertsLoading(false); }
  }, []);

  const fetchMetrics = useCallback(async () => {
    try { const data = await api.getMetrics(); setMetrics(data); setMetricsLoading(false); } catch {}
  }, []);

  useEffect(() => {
    if (!authed) return;
    fetchAlerts(); fetchMetrics();
    const t1 = setInterval(fetchAlerts,  10000);
    const t2 = setInterval(fetchMetrics, 15000);
    return () => { clearInterval(t1); clearInterval(t2); };
  }, [authed, fetchAlerts, fetchMetrics]);

  const onEscalate = id => { setAlerts(p => p.map(a => a.id===id?{...a,status:"Escalated"}:a)); fetchMetrics(); };
  const onDismiss  = id => { setAlerts(p => p.map(a => a.id===id?{...a,status:"Dismissed",classification:"False Positive"}:a)); fetchMetrics(); };

  if (!authed) return <LoginPage onLogin={() => setAuthed(true)}/>;

  const filtered = alerts.filter(a => {
    if (sevFilter!=="All" && a.severity!==sevFilter) return false;
    if (clsFilter!=="All" && a.classification!==clsFilter) return false;
    return true;
  });

  const critCount = alerts.filter(a=>a.severity==="Critical").length;
  const newCount  = alerts.filter(a=>a.status==="New").length;
  const tpCount   = alerts.filter(a=>a.classification==="True Positive").length;

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800&display=swap');
        *{box-sizing:border-box;margin:0;padding:0}
        html,body,#root{width:100%;height:100%;overflow:hidden;background:#0a0a0f}
        ::-webkit-scrollbar{width:3px;height:3px}
        ::-webkit-scrollbar-track{background:rgba(255,255,255,0.02)}
        ::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.1);border-radius:2px}
        @keyframes shimmer{0%{transform:translateX(-200%)}100%{transform:translateX(200%)}}
        @keyframes spin{to{transform:rotate(360deg)}}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
        @keyframes modalIn{from{opacity:0;transform:scale(.96) translateY(12px)}to{opacity:1;transform:scale(1) translateY(0)}}
        @keyframes cardIn{from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:translateX(0)}}
      `}</style>

      <div style={{ display:"flex", height:"100vh", width:"100vw", background:"#0a0a0f", fontFamily:"'Inter',sans-serif", color:"#fff", overflow:"hidden" }}>
        {/* SIDEBAR */}
        <div style={{ width:196, background:"#07070c", borderRight:"1px solid rgba(255,255,255,0.055)", display:"flex", flexDirection:"column", flexShrink:0 }}>
          <div style={{ padding:"18px 16px 14px", borderBottom:"1px solid rgba(255,255,255,0.055)" }}>
            <div style={{ display:"flex", alignItems:"center", gap:9 }}>
              <div style={{ width:28, height:28, background:"linear-gradient(135deg,#3b82f6,#1e40af)", borderRadius:4, display:"flex", alignItems:"center", justifyContent:"center", fontSize:14 }}>⬡</div>
              <div>
                <div style={{ fontSize:12, fontWeight:800, letterSpacing:"0.06em" }}>KPMG MDR</div>
                <div style={{ fontSize:8, color:"rgba(255,255,255,0.28)", letterSpacing:"0.14em" }}>SOC COPILOT</div>
              </div>
            </div>
          </div>
          <div style={{ padding:"12px 16px", borderBottom:"1px solid rgba(255,255,255,0.055)" }}>
            <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:5 }}>
              <div style={{ width:26, height:26, borderRadius:"50%", background:"linear-gradient(135deg,rgba(59,130,246,.3),rgba(30,64,175,.3))", border:"1px solid rgba(59,130,246,.22)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:10, fontWeight:700, color:"#3b82f6" }}>SR</div>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:11, fontWeight:600, color:"rgba(255,255,255,.82)" }}>Aashish Koundinya</div>
                <div style={{ fontSize:9, color:"rgba(255,255,255,.3)" }}>L1 Analyst</div>
              </div>
              <div style={{ display:"flex", alignItems:"center", gap:3 }}>
                <div style={{ width:5, height:5, borderRadius:"50%", background:"#22c55e", animation:"pulse 2s infinite" }}/>
                <span style={{ fontSize:8, color:"#22c55e", fontWeight:600 }}>LIVE</span>
              </div>
            </div>
            <div style={{ fontSize:9, color:"rgba(255,255,255,.2)", fontFamily:"'JetBrains Mono',monospace" }}>Shift 08:00–20:00 UTC</div>
          </div>
          <div style={{ padding:"10px 16px", borderBottom:"1px solid rgba(255,255,255,0.055)" }}>
            <div style={{ fontSize:9, color:"rgba(255,255,255,.22)", letterSpacing:"0.1em", marginBottom:8 }}>QUEUE STATUS</div>
            {[{l:"Critical",v:critCount,c:"#ef4444"},{l:"New Alerts",v:newCount,c:"#3b82f6"},{l:"True Pos",v:tpCount,c:"#f97316"},{l:"Total",v:alerts.length,c:"rgba(255,255,255,.65)"}].map(({l,v,c})=>(
              <div key={l} style={{ display:"flex", justifyContent:"space-between", marginBottom:5 }}>
                <span style={{ fontSize:10, color:"rgba(255,255,255,.32)" }}>{l}</span>
                <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:12, fontWeight:700, color:c }}>{v}</span>
              </div>
            ))}
          </div>
          <div style={{ padding:"10px 16px", flex:1 }}>
            <div style={{ fontSize:9, color:"rgba(255,255,255,.22)", letterSpacing:"0.1em", marginBottom:8 }}>INTEGRATIONS</div>
            {[
              {l:"FastAPI",    s:backendOk===null?"Checking…":backendOk?"Connected":"⚠ Offline", c:backendOk===null?"#eab308":backendOk?"#22c55e":"#ef4444"},
              {l:"Claude AI",  s:"Active",    c:"#22c55e"},
              {l:"PostgreSQL", s:"Connected", c:"#22c55e"},
              {l:"Slack",      s:"Online",    c:"#22c55e"},
            ].map(({l,s,c})=>(
              <div key={l} style={{ display:"flex", alignItems:"center", gap:6, marginBottom:7 }}>
                <div style={{ width:5, height:5, borderRadius:"50%", background:c }}/>
                <span style={{ fontSize:10, color:"rgba(255,255,255,.35)", flex:1 }}>{l}</span>
                <span style={{ fontSize:9, color:c }}>{s}</span>
              </div>
            ))}
          </div>
          <div style={{ padding:"10px 16px", borderTop:"1px solid rgba(255,255,255,0.055)" }}>
            <button onClick={() => { sessionStorage.removeItem("soc_auth"); setAuthed(false); }}
              style={{ width:"100%", padding:"7px 0", background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.07)", borderRadius:3, color:"rgba(255,255,255,0.3)", fontSize:10, cursor:"pointer" }}>
              Sign Out
            </button>
          </div>
          <div style={{ padding:"12px 16px", borderTop:"1px solid rgba(255,255,255,0.055)" }}>
            <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:19, fontWeight:700, color:"rgba(255,255,255,.78)" }}>{time.toISOString().slice(11,19)}</div>
            <div style={{ fontSize:9, color:"rgba(255,255,255,.2)", marginTop:2 }}>{time.toDateString()}</div>
          </div>
        </div>

        {/* MAIN */}
        <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden", minWidth:0 }}>
          <div style={{ padding:"9px 18px", borderBottom:"1px solid rgba(255,255,255,0.055)", display:"flex", alignItems:"center", gap:12, flexShrink:0, background:"rgba(255,255,255,0.007)" }}>
            <div style={{ fontSize:12, fontWeight:700, color:"rgba(255,255,255,.55)" }}>Dashboard</div>
            <div style={{ width:1, height:14, background:"rgba(255,255,255,.07)" }}/>
            <div style={{ display:"flex", alignItems:"center", gap:5 }}>
              <span style={{ fontSize:9, color:"rgba(255,255,255,.22)", letterSpacing:"0.08em" }}>SEV</span>
              {["All","Critical","High","Medium","Low"].map(s => {
                const active=sevFilter===s; const c=s==="All"?null:SEV[s];
                return <button key={s} onClick={()=>setSevFilter(s)} style={{ padding:"3px 8px", borderRadius:2, fontSize:10, cursor:"pointer", border:`1px solid ${active?(c?c.border:"rgba(255,255,255,.2)"):"rgba(255,255,255,.06)"}`, background:active?(c?c.bg:"rgba(255,255,255,.06)"):"transparent", color:active?(c?c.color:"rgba(255,255,255,.8)"):"rgba(255,255,255,.25)" }}>{s}</button>;
              })}
            </div>
            <div style={{ width:1, height:14, background:"rgba(255,255,255,.07)" }}/>
            <div style={{ display:"flex", alignItems:"center", gap:5 }}>
              <span style={{ fontSize:9, color:"rgba(255,255,255,.22)", letterSpacing:"0.08em" }}>CLASS</span>
              {[["All","All"],["True Positive","TP"],["False Positive","FP"],["Needs Review","NR"]].map(([val,lbl]) => {
                const active=clsFilter===val;
                return <button key={val} onClick={()=>setClsFilter(val)} style={{ padding:"3px 8px", borderRadius:2, fontSize:10, cursor:"pointer", border:`1px solid ${active?"rgba(255,255,255,.2)":"rgba(255,255,255,.06)"}`, background:active?"rgba(255,255,255,.06)":"transparent", color:active?"rgba(255,255,255,.8)":"rgba(255,255,255,.25)" }}>{lbl}</button>;
              })}
            </div>
            <div style={{ flex:1 }}/>
            <div style={{ display:"flex", alignItems:"center", gap:5 }}>
              {alertsLoading?<Spinner color="#3b82f6" size={8}/>:<div style={{ width:6, height:6, borderRadius:"50%", background:backendOk?"#22c55e":"#ef4444", animation:"pulse 2s infinite" }}/>}
              <span style={{ fontSize:10, color:"rgba(255,255,255,.28)", fontFamily:"'JetBrains Mono',monospace" }}>{backendOk===false?"BACKEND OFFLINE":"LIVE · AUTO-REFRESH 10s"}</span>
            </div>
          </div>

          <div style={{ flex:1, overflow:"hidden", display:"grid", gridTemplateColumns:"1fr 320px" }}>
            <div style={{ overflowY:"auto", padding:"14px 16px", borderRight:"1px solid rgba(255,255,255,0.055)" }}>
              <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:10 }}>
                <div style={{ fontSize:10, fontWeight:600, color:"rgba(255,255,255,.28)", letterSpacing:"0.1em" }}>ALERT QUEUE</div>
                <div style={{ padding:"1px 7px", borderRadius:10, fontSize:10, fontWeight:700, background:"#ef4444", color:"#fff" }}>{filtered.length}</div>
                {newCount>0&&<div style={{ display:"flex", alignItems:"center", gap:4, fontSize:9, color:"#3b82f6" }}><div style={{ width:5, height:5, borderRadius:"50%", background:"#3b82f6", animation:"pulse 1.5s infinite" }}/>{newCount} new</div>}
              </div>
              {backendOk===false?(
                <div style={{ padding:"24px 16px", background:"rgba(239,68,68,0.05)", border:"1px solid rgba(239,68,68,0.2)", borderRadius:4, color:"rgba(255,255,255,0.6)", fontSize:12, lineHeight:1.8 }}>
                  <div style={{ color:"#ef4444", fontWeight:700, marginBottom:6 }}>⚠ Backend Offline</div>
                  <code style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:10, color:"#3b82f6" }}>cd backend && uvicorn main:app --reload</code>
                </div>
              ):alertsLoading?(
                <div style={{ display:"flex", alignItems:"center", gap:8, color:"rgba(255,255,255,0.3)", fontSize:12, padding:"20px 0" }}><Spinner color="#3b82f6" size={14}/>Connecting…</div>
              ):filtered.length===0?(
                <div style={{ textAlign:"center", padding:"40px 0", color:"rgba(255,255,255,.2)", fontSize:12, lineHeight:2 }}>No alerts yet.<br/><span style={{ fontSize:10, fontFamily:"'JetBrains Mono',monospace", color:"rgba(255,255,255,.15)" }}>Start the log generator to see alerts appear here.</span></div>
              ):(
                filtered.map(a=><AlertCard key={a.id} alert={a} onClick={()=>setModal(a)} isNew={newIds.has(a.id)}/>)
              )}
            </div>
            <div style={{ overflowY:"auto", padding:"14px 16px" }}>
              <div style={{ fontSize:10, fontWeight:600, color:"rgba(255,255,255,.28)", letterSpacing:"0.1em", marginBottom:10 }}>SHIFT METRICS</div>
              <MetricsPanel metrics={metrics} loading={metricsLoading}/>
            </div>
          </div>
        </div>
      </div>

      {modal&&<AlertModal alertSummary={modal} onClose={()=>setModal(null)} onEscalate={onEscalate} onDismiss={onDismiss}/>}
    </>
  );
}