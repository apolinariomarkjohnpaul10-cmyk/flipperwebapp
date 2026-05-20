import { useState, useRef } from "react";

const API = "https://flipperwebapp.onrender.com";

function Section({ title, children }) {
  return (
    <div style={{ background: "#111", border: "1px solid #333", borderRadius: 8, padding: 20, marginBottom: 20 }}>
      <h2 style={{ color: "#00ff88", marginTop: 0, fontFamily: "monospace" }}>⚡ {title}</h2>
      {children}
    </div>
  );
}

function Input({ label, value, onChange, placeholder }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <label style={{ color: "#aaa", fontSize: 13 }}>{label}</label><br />
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        style={{ background: "#222", color: "#fff", border: "1px solid #444", borderRadius: 4, padding: "6px 10px", width: "100%", fontFamily: "monospace" }}
      />
    </div>
  );
}

function Button({ onClick, children, loading }) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      style={{ background: loading ? "#333" : "#00ff88", color: "#000", border: "none", borderRadius: 4, padding: "8px 20px", fontWeight: "bold", cursor: loading ? "not-allowed" : "pointer", fontFamily: "monospace" }}
    >
      {loading ? "Running..." : children}
    </button>
  );
}

function Result({ data }) {
  if (!data) return null;
  return (
    <pre style={{ background: "#0a0a0a", color: "#00ff88", padding: 12, borderRadius: 4, overflowX: "auto", fontSize: 12, marginTop: 12 }}>
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

// ── ARP Sweep ──────────────────────────────────────────────
function ArpSweep() {
  const [cidr, setCidr] = useState("10.104.85.0/24");
  const [timeout, setTimeout_] = useState("2.0");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true); setResult(null);
    try {
      const res = await fetch(`${API}/api/recon/arp-sweep`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_cidr: cidr, timeout: parseFloat(timeout), include_ipv6: false }),
      });
      setResult(await res.json());
    } catch (e) { setResult({ error: e.message }); }
    setLoading(false);
  };

  return (
    <Section title="ARP Sweep — Find Devices on LAN">
      <Input label="Network CIDR" value={cidr} onChange={setCidr} placeholder="192.168.1.0/24" />
      <Input label="Timeout (seconds)" value={timeout} onChange={setTimeout_} placeholder="2.0" />
      <Button onClick={run} loading={loading}>Run ARP Sweep</Button>
      {result?.hosts && (
        <div style={{ marginTop: 12 }}>
          <p style={{ color: "#aaa", margin: "8px 0" }}>Found <strong style={{ color: "#00ff88" }}>{result.hosts_found}</strong> hosts:</p>
          <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "monospace", fontSize: 12 }}>
            <thead><tr style={{ color: "#666" }}>
              <th style={{ textAlign: "left", padding: "4px 8px" }}>IP</th>
              <th style={{ textAlign: "left", padding: "4px 8px" }}>MAC</th>
              <th style={{ textAlign: "left", padding: "4px 8px" }}>Hostname</th>
            </tr></thead>
            <tbody>
              {result.hosts.map((h, i) => (
                <tr key={i} style={{ borderTop: "1px solid #222" }}>
                  <td style={{ padding: "4px 8px", color: "#00ff88" }}>{h.ip}</td>
                  <td style={{ padding: "4px 8px", color: "#fff" }}>{h.mac}</td>
                  <td style={{ padding: "4px 8px", color: "#aaa" }}>{h.hostname || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {result?.error && <Result data={result} />}
    </Section>
  );
}

// ── SYN Scan ───────────────────────────────────────────────
function SynScan() {
  const [target, setTarget] = useState("10.104.85.96");
  const [ports, setPorts] = useState("22,80,443,8080,1-100");
  const [timeout, setTimeout_] = useState("1.0");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true); setResult(null);
    try {
      const res = await fetch(`${API}/api/recon/syn-scan`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, ports, timeout: parseFloat(timeout) }),
      });
      setResult(await res.json());
    } catch (e) { setResult({ error: e.message }); }
    setLoading(false);
  };

  return (
    <Section title="TCP SYN Scan — Find Open Ports">
      <Input label="Target IP" value={target} onChange={setTarget} placeholder="192.168.1.1" />
      <Input label="Ports (e.g. 22,80,443 or 1-1000)" value={ports} onChange={setPorts} placeholder="22,80,443" />
      <Input label="Timeout (seconds)" value={timeout} onChange={setTimeout_} placeholder="1.0" />
      <Button onClick={run} loading={loading}>Run SYN Scan</Button>
      {result && !result.error && (
        <div style={{ marginTop: 12 }}>
          <p style={{ color: "#aaa", fontSize: 13 }}>
            Scanned <strong style={{ color: "#fff" }}>{result.ports_scanned}</strong> ports —{" "}
            <strong style={{ color: "#00ff88" }}>{result.open?.length} open</strong>,{" "}
            <strong style={{ color: "#ff4444" }}>{result.closed_count} closed</strong>,{" "}
            <strong style={{ color: "#ffaa00" }}>{result.filtered_count} filtered</strong>
          </p>
          {result.open?.length > 0 && (
            <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "monospace", fontSize: 12 }}>
              <thead><tr style={{ color: "#666" }}>
                <th style={{ textAlign: "left", padding: "4px 8px" }}>Port</th>
                <th style={{ textAlign: "left", padding: "4px 8px" }}>State</th>
              </tr></thead>
              <tbody>
                {result.open.map((p, i) => (
                  <tr key={i} style={{ borderTop: "1px solid #222" }}>
                    <td style={{ padding: "4px 8px", color: "#00ff88" }}>{p.port}</td>
                    <td style={{ padding: "4px 8px", color: "#fff" }}>{p.state}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
      {result?.error && <Result data={result} />}
    </Section>
  );
}

// ── Nmap Scan ──────────────────────────────────────────────
function NmapScan() {
  const [target, setTarget] = useState("10.104.85.0/24");
  const [scanType, setScanType] = useState("ping");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true); setResult(null);
    try {
      const res = await fetch(`${API}/api/scan`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, scan_type: scanType }),
      });
      const { job_id } = await res.json();
      for (let i = 0; i < 60; i++) {
        await new Promise(r => globalThis.setTimeout(r, 2000));
        const poll = await fetch(`${API}/api/scan/${job_id}`, { credentials: "include" });
        const data = await poll.json();
        if (data.status === "completed" || data.status === "error") { setResult(data); break; }
        setResult({ status: data.status, message: `Polling... (${i + 1})` });
      }
    } catch (e) { setResult({ error: e.message }); }
    setLoading(false);
  };

  return (
    <Section title="Nmap Scan">
      <Input label="Target (IP, CIDR, or hostname)" value={target} onChange={setTarget} placeholder="192.168.1.0/24" />
      <div style={{ marginBottom: 10 }}>
        <label style={{ color: "#aaa", fontSize: 13 }}>Scan Type</label><br />
        <select value={scanType} onChange={e => setScanType(e.target.value)}
          style={{ background: "#222", color: "#fff", border: "1px solid #444", borderRadius: 4, padding: "6px 10px", fontFamily: "monospace" }}>
          <option value="ping">Ping — Host discovery only</option>
          <option value="syn">SYN — Stealth port scan (requires admin)</option>
          <option value="ports">Ports — Full TCP connect scan</option>
        </select>
      </div>
      <Button onClick={run} loading={loading}>Run Nmap Scan</Button>
      <Result data={result} />
    </Section>
  );
}

// ── DHCP Sniffer ───────────────────────────────────────────
function DhcpSniffer() {
  const [running, setRunning] = useState(false);
  const [devices, setDevices] = useState([]);
  const [status, setStatus] = useState("Idle");
  const wsRef = useRef(null);

  const start = () => {
    const ws = new WebSocket("wss://flipperwebapp.onrender.com/api/recon/ws/dhcp-sniff");
    wsRef.current = ws;

    ws.onopen = () => {
      setRunning(true);
      setStatus("Sniffing DHCP packets... disconnect & reconnect your phone to Wi-Fi now!");
    };
    ws.onmessage = (e) => {
      const data = JSON.parse(e.data);
      if (data.event === "dhcp_hostname") {
        setDevices(prev => {
          const exists = prev.find(d => d.mac === data.mac);
          if (exists) return prev.map(d => d.mac === data.mac ? { ...d, ...data } : d);
          return [...prev, data];
        });
      }
    };
    ws.onclose = () => { setRunning(false); setStatus("Stopped."); };
    ws.onerror = () => { setRunning(false); setStatus("WebSocket error — is the backend running?"); };
  };

  const stop = () => { wsRef.current?.close(); };

  return (
    <Section title="DHCP Sniffer — Catch Device Names">
      <p style={{ color: "#aaa", fontSize: 13, marginTop: 0 }}>
        Passively listens for DHCP packets. To reveal your phone's hostname,
        <strong style={{ color: "#00ff88" }}> disconnect and reconnect it to Wi-Fi</strong> while sniffing.
      </p>
      <div style={{ display: "flex", gap: 10, marginBottom: 12 }}>
        <Button onClick={start} loading={running}>▶ Start Sniffing</Button>
        {running && (
          <button onClick={stop}
            style={{ background: "#ff4444", color: "#fff", border: "none", borderRadius: 4, padding: "8px 20px", fontWeight: "bold", cursor: "pointer", fontFamily: "monospace" }}>
            ■ Stop
          </button>
        )}
      </div>
      <p style={{ color: running ? "#00ff88" : "#555", fontSize: 12, margin: "0 0 12px" }}>
        ● {status}
      </p>
      {devices.length > 0 && (
        <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "monospace", fontSize: 12 }}>
          <thead>
            <tr style={{ color: "#666" }}>
              <th style={{ textAlign: "left", padding: "4px 8px" }}>MAC</th>
              <th style={{ textAlign: "left", padding: "4px 8px" }}>IP</th>
              <th style={{ textAlign: "left", padding: "4px 8px" }}>Hostname</th>
              <th style={{ textAlign: "left", padding: "4px 8px" }}>Vendor</th>
              <th style={{ textAlign: "left", padding: "4px 8px" }}>Type</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d, i) => (
              <tr key={i} style={{ borderTop: "1px solid #222" }}>
                <td style={{ padding: "4px 8px", color: "#fff" }}>{d.mac}</td>
                <td style={{ padding: "4px 8px", color: "#00ff88" }}>{d.ip}</td>
                <td style={{ padding: "4px 8px", color: "#00ff88", fontWeight: "bold" }}>{d.hostname || "—"}</td>
                <td style={{ padding: "4px 8px", color: "#aaa" }}>{d.vendor || "—"}</td>
                <td style={{ padding: "4px 8px", color: "#ffaa00" }}>{d.type}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {devices.length === 0 && running && (
        <p style={{ color: "#555", fontSize: 12 }}>Waiting for DHCP packets... disconnect and reconnect a device to Wi-Fi.</p>
      )}
    </Section>
  );
}

// ── Control Panel ──────────────────────────────────────────
function ControlPanel() {
  const [targetIp, setTargetIp] = useState("192.168.137.2");
  const [gatewayIp, setGatewayIp] = useState("192.168.137.1");
  const [activeFeature, setActiveFeature] = useState(null);
  const [logs, setLogs] = useState([]);
  const [status, setStatus] = useState("Idle");

  // DNS spoof specific
  const [domain, setDomain] = useState("example.com");
  const [redirectIp, setRedirectIp] = useState("192.168.137.1");

  // Throttle specific
  const [dropPercent, setDropPercent] = useState("70");
  const wsRef = useRef(null);

  const addLog = (msg, color = "#00ff88") => {
    setLogs(prev => [{msg, color, time: new Date().toLocaleTimeString()}, ...prev].slice(0, 100));
  };

  const stop = () => {
    wsRef.current?.close();
    setActiveFeature(null);
    setStatus("Stopped — ARP tables restored.");
  };

  const startFeature = (feature) => {
    let url = `wss://flipperwebapp.onrender.com/api/control/ws/${feature}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;
    let payload = { target_ip: targetIp, gateway_ip: gatewayIp };

    if (feature === "dns-spoof") payload = { ...payload, domain, redirect_ip: redirectIp };
    if (feature === "throttle") payload = { ...payload, drop_percent: parseInt(dropPercent) };

    ws.onopen = () => {
      setActiveFeature(feature);
      setStatus(`Running: ${feature}`);
      ws.send(JSON.stringify(payload));
    };

    ws.onmessage = (e) => {
      const data = JSON.parse(e.data);
      switch (data.event) {
        case "inspect_started":
          addLog(`🔍 Inspecting traffic from ${data.target}`, "#00ff88"); break;
        case "traffic":
          addLog(`[${data.type}] ${data.src} → ${data.detail}`,
            data.type === "HTTPS" ? "#00aaff" : data.type === "HTTP" ? "#ffaa00" : "#fff"); break;
        case "dns_spoof_started":
          addLog(`🎯 DNS Spoof active: ${data.domain} → ${data.redirect_to}`, "#ff4444"); break;
        case "dns_spoofed":
          addLog(`✅ Spoofed: ${data.domain} → ${data.redirected_to}`, "#ff4444"); break;
        case "throttle_started":
          addLog(`🐢 Throttling ${data.target} (dropping ${data.drop_percent}% of packets)`, "#ffaa00"); break;
        case "packet_dropped":
          if (data.dropped % 20 === 0)
            addLog(`📉 Dropped: ${data.dropped} | Forwarded: ${data.forwarded}`, "#ffaa00"); break;
        case "block_started":
          addLog(`🚫 Internet BLOCKED for ${data.target}`, "#ff4444"); break;
        case "blocking":
          addLog(`🚫 ${data.target} — ${data.status}`, "#ff4444"); break;
        case "mitm_started":
          addLog(`👁 MITM active — all traffic from ${data.target} passes through you`, "#ff4444"); break;
        case "mitm_traffic":
          if (data.packets_intercepted % 50 === 0)
            addLog(`📦 Intercepted ${data.packets_intercepted} packets`, "#ff4444"); break;
        case "error":
          addLog(`❌ Error: ${data.message}`, "#ff4444"); break;
        default:
          addLog(JSON.stringify(data)); break;
      }
    };

    ws.onclose = () => {
      setActiveFeature(null);
      setStatus("Stopped — ARP tables restored.");
      addLog("⚠ Connection closed — ARP restored", "#aaa");
    };

    ws.onerror = () => {
      setActiveFeature(null);
      setStatus("WebSocket error");
      addLog("❌ WebSocket error", "#ff4444");
    };
  };

  const features = [
    { id: "inspect",   label: "🔍 Traffic Inspector",    desc: "See what sites/apps the device is using" },
    { id: "dns-spoof", label: "🎯 DNS Manipulator",       desc: "Redirect a domain to a different IP" },
    { id: "throttle",  label: "🐢 Bandwidth Throttler",   desc: "Slow down the device's connection" },
    { id: "block",     label: "🚫 Block Internet",        desc: "Cut off device from the internet" },
    { id: "arp-spoof", label: "👁 ARP Spoof / MITM",      desc: "Intercept all traffic from the device" },
  ];

  return (
    <Section title="Hotspot Control Panel">

      <Input label="Target Device IP" value={targetIp} onChange={setTargetIp} placeholder="192.168.137.2" />
      <Input label="Gateway / Your Hotspot IP" value={gatewayIp} onChange={setGatewayIp} placeholder="192.168.137.1" />
      
      {activeFeature === "dns-spoof" || !activeFeature ? (
        <div style={{ display: activeFeature && activeFeature !== "dns-spoof" ? "none" : "block" }}>
          <Input label="Domain to redirect (DNS Spoof)" value={domain} onChange={setDomain} placeholder="example.com" />
          <Input label="Redirect to IP (DNS Spoof)" value={redirectIp} onChange={setRedirectIp} placeholder="192.168.137.1" />
        </div>
      ) : null}

      {activeFeature === "throttle" || !activeFeature ? (
        <div style={{ display: activeFeature && activeFeature !== "throttle" ? "none" : "block" }}>
          <Input label="Drop % (Throttle — higher = slower)" value={dropPercent} onChange={setDropPercent} placeholder="70" />
        </div>
      ) : null}

      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, margin: "12px 0" }}>
        {features.map(f => (
          <button key={f.id}
            onClick={() => activeFeature ? stop() : startFeature(f.id)}
            disabled={activeFeature && activeFeature !== f.id}
            title={f.desc}
            style={{
              background: activeFeature === f.id ? "#ff4444" : activeFeature ? "#222" : "#1a1a1a",
              color: activeFeature === f.id ? "#fff" : activeFeature ? "#555" : "#00ff88",
              border: `1px solid ${activeFeature === f.id ? "#ff4444" : "#333"}`,
              borderRadius: 4, padding: "8px 14px", cursor: activeFeature && activeFeature !== f.id ? "not-allowed" : "pointer",
              fontFamily: "monospace", fontSize: 12, fontWeight: "bold",
            }}>
            {activeFeature === f.id ? `■ Stop ${f.label}` : f.label}
          </button>
        ))}
      </div>
      
      <p style={{ color: activeFeature ? "#ff4444" : "#555", fontSize: 12, margin: "4px 0 12px" }}>
        ● {status}
      </p>

      {logs.length > 0 && (
        <div style={{ background: "#0a0a0a", borderRadius: 4, padding: 10, maxHeight: 300, overflowY: "auto" }}>
          {logs.map((l, i) => (
            <div key={i} style={{ fontFamily: "monospace", fontSize: 11, color: l.color, marginBottom: 2 }}>
              <span style={{ color: "#444" }}>[{l.time}]</span> {l.msg}
            </div>
          ))}
        </div>
      )}
    </Section>
  );
}

// ── App ────────────────────────────────────────────────────
export default function App() {
  const [health, setHealth] = useState(null);

  const checkHealth = async () => {
    try {
      const res = await fetch(`${API}/api/health`, { credentials: "include" });
      setHealth(await res.json());
    } catch { setHealth({ error: "Backend not reachable" }); }
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0d0d0d", color: "#fff", fontFamily: "monospace", padding: 24 }}>
      <div style={{ maxWidth: 800, margin: "0 auto" }}>
        <h1 style={{ color: "#00ff88", textAlign: "center", letterSpacing: 4, marginBottom: 4 }}>
          🐬 FLIPPER ZERO WEB APP
        </h1>
        <p style={{ textAlign: "center", color: "#555", marginBottom: 24 }}>Network Recon & Analysis Tool</p>
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <Button onClick={checkHealth}>Check Backend</Button>
          {health && <span style={{ marginLeft: 12, color: health.error ? "#ff4444" : "#00ff88" }}>
            {health.error || `✓ ${health.message}`}
          </span>}
        </div>
        <ArpSweep />
        <SynScan />
        <NmapScan />
        <DhcpSniffer />
        <ControlPanel />
      </div>
    </div>
  );
}