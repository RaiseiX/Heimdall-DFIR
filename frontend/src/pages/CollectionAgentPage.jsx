import { useState, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Terminal, Copy, Download, CheckCircle } from 'lucide-react';

const WIN_ARTIFACT_LABELS = {
  evtx: 'EVTX logs (Windows Events)',
  prefetch: 'Prefetch (executables)',
  mft: 'MFT (NTFS — raw)',
  registry: 'Registry hives (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER)',
  amcache: 'Amcache.hve',
  lnk: 'LNK files & Jump Lists',
  sysmon: 'Logs Sysmon',
  scheduled_tasks: 'Scheduled tasks',
  ram: 'RAM (WinPmem)',
  pcap: 'Network capture (netsh)',
};

const LIN_ARTIFACT_LABELS = {
  syslog: 'System logs (/var/log/syslog, auth.log…)',
  process: 'Running processes (ps, cmdlines)',
  network: 'Network (ss, ip route, iptables)',
  cron: 'Crontabs',
  persistence: 'Persistence (init.d, systemd, rc.local)',
  ram: 'RAM (/dev/mem)',
};

function generateWindowsScript({ caseNum, analyst, outputDir, artifacts, compress, hashFile }) {
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const lines = [];
  lines.push(`# Heimdall DFIR Collection Agent — Windows`);
  lines.push(`# Case: ${caseNum || 'N/A'} | Analyst: ${analyst || 'N/A'} | Generated: ${new Date().toISOString().slice(0, 16)}`);
  lines.push(`# EXECUTE AS ADMINISTRATOR`);
  lines.push(``);
  lines.push(`$OutDir = "${outputDir}\\${date}"`);
  lines.push(`New-Item -ItemType Directory -Force -Path $OutDir | Out-Null`);
  lines.push(``);

  if (artifacts.evtx) {
    lines.push(`# EVTX Windows Event Logs`);
    lines.push(`Write-Host "[*] Collecting EVTX..."`);
    lines.push(`New-Item -ItemType Directory -Force -Path "$OutDir\\evtx" | Out-Null`);
    lines.push(`Copy-Item "C:\\Windows\\System32\\winevt\\Logs\\*" "$OutDir\\evtx\\" -Force -ErrorAction SilentlyContinue`);
    lines.push(``);
  }

  if (artifacts.prefetch) {
    lines.push(`# Prefetch`);
    lines.push(`Write-Host "[*] Collecting Prefetch..."`);
    lines.push(`New-Item -ItemType Directory -Force -Path "$OutDir\\prefetch" | Out-Null`);
    lines.push(`Copy-Item "C:\\Windows\\Prefetch\\*.pf" "$OutDir\\prefetch\\" -Force -ErrorAction SilentlyContinue`);
    lines.push(``);
  }

  if (artifacts.mft) {
    lines.push(`# MFT (raw NTFS)`);
    lines.push(`Write-Host "[*] Collecting MFT (NTFS raw)..."`);
    lines.push(`New-Item -ItemType Directory -Force -Path "$OutDir\\mft" | Out-Null`);
    lines.push(`try {`);
    lines.push(`  $vol = [System.IO.FileStream]::new('\\\\.\\C:', [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)`);
    lines.push(`  $buf = New-Object byte[] 1024`);
    lines.push(`  $vol.Read($buf, 0, 1024) | Out-Null`);
    lines.push(`  $vol.Close()`);
    lines.push(`  Write-Host "[+] MFT: use FTK Imager or Zimmerman MFTECmd for full extraction"`);
    lines.push(`} catch { Write-Host "[-] MFT: insufficient privileges" }`);
    lines.push(``);
  }

  if (artifacts.registry) {
    lines.push(`# Registry`);
    lines.push(`Write-Host "[*] Collecting Registry..."`);
    lines.push(`New-Item -ItemType Directory -Force -Path "$OutDir\\registry" | Out-Null`);
    lines.push(`reg save HKLM\\SAM "$OutDir\\registry\\SAM.hiv" /y 2>$null`);
    lines.push(`reg save HKLM\\SYSTEM "$OutDir\\registry\\SYSTEM.hiv" /y 2>$null`);
    lines.push(`reg save HKLM\\SOFTWARE "$OutDir\\registry\\SOFTWARE.hiv" /y 2>$null`);
    lines.push(`reg save HKLM\\SECURITY "$OutDir\\registry\\SECURITY.hiv" /y 2>$null`);
    lines.push(`Copy-Item "$env:USERPROFILE\\NTUSER.DAT" "$OutDir\\registry\\NTUSER.DAT" -Force -ErrorAction SilentlyContinue`);
    lines.push(``);
  }

  if (artifacts.amcache) {
    lines.push(`# Amcache`);
    lines.push(`Write-Host "[*] Collecting Amcache..."`);
    lines.push(`New-Item -ItemType Directory -Force -Path "$OutDir\\amcache" | Out-Null`);
    lines.push(`Copy-Item "C:\\Windows\\AppCompat\\Programs\\Amcache.hve" "$OutDir\\amcache\\" -Force -ErrorAction SilentlyContinue`);
    lines.push(``);
  }

  if (artifacts.lnk) {
    lines.push(`# LNK & Jump Lists`);
    lines.push(`Write-Host "[*] Collecting LNK & Jump Lists..."`);
    lines.push(`New-Item -ItemType Directory -Force -Path "$OutDir\\lnk" | Out-Null`);
    lines.push(`Copy-Item "$env:APPDATA\\Microsoft\\Windows\\Recent\\*" "$OutDir\\lnk\\" -Recurse -Force -ErrorAction SilentlyContinue`);
    lines.push(`New-Item -ItemType Directory -Force -Path "$OutDir\\jumplists" | Out-Null`);
    lines.push(`Copy-Item "$env:APPDATA\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*" "$OutDir\\jumplists\\" -Force -ErrorAction SilentlyContinue`);
    lines.push(`Copy-Item "$env:APPDATA\\Microsoft\\Windows\\Recent\\CustomDestinations\\*" "$OutDir\\jumplists\\" -Force -ErrorAction SilentlyContinue`);
    lines.push(``);
  }

  if (artifacts.sysmon) {
    lines.push(`# Sysmon`);
    lines.push(`Write-Host "[*] Collecting Sysmon..."`);
    lines.push(`Copy-Item "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx" "$OutDir\\evtx\\" -Force -ErrorAction SilentlyContinue`);
    lines.push(``);
  }

  if (artifacts.scheduled_tasks) {
    lines.push(`# Scheduled Tasks`);
    lines.push(`Write-Host "[*] Collecting scheduled tasks..."`);
    lines.push(`New-Item -ItemType Directory -Force -Path "$OutDir\\tasks" | Out-Null`);
    lines.push(`Copy-Item "C:\\Windows\\System32\\Tasks\\*" "$OutDir\\tasks\\" -Recurse -Force -ErrorAction SilentlyContinue`);
    lines.push(``);
  }

  if (artifacts.ram) {
    lines.push(`# RAM (WinPmem)`);
    lines.push(`Write-Host "[*] Collecting RAM (WinPmem required)..."`);
    lines.push(`New-Item -ItemType Directory -Force -Path "$OutDir\\ram" | Out-Null`);
    lines.push(`if (Get-Command winpmem.exe -ErrorAction SilentlyContinue) {`);
    lines.push(`  winpmem.exe "$OutDir\\ram\\memory.raw"`);
    lines.push(`} else { Write-Host "[-] WinPmem not found — download from https://github.com/Velocidex/WinPmem" }`);
    lines.push(``);
  }

  if (artifacts.pcap) {
    lines.push(`# Network Capture`);
    lines.push(`Write-Host "[*] Starting network capture..."`);
    lines.push(`New-Item -ItemType Directory -Force -Path "$OutDir\\pcap" | Out-Null`);
    lines.push(`netsh trace start capture=yes traceFile="$OutDir\\pcap\\capture.etl" maxsize=512 overwrite=yes`);
    lines.push(`Write-Host "[!] Network capture started. To stop: netsh trace stop"`);
    lines.push(``);
  }

  if (compress) {
    lines.push(`# Compression`);
    lines.push(`Write-Host "[*] Compressing..."`);
    lines.push(`Compress-Archive -Path $OutDir -DestinationPath "$OutDir.zip" -CompressionLevel Optimal -Force`);
    lines.push(``);
  }

  if (hashFile) {
    lines.push(`# SHA-256 Hash`);
    const target = compress ? `"$OutDir.zip"` : `$OutDir`;
    lines.push(`$hash = Get-FileHash ${target} -Algorithm SHA256`);
    lines.push(`Write-Host "[+] SHA256: $($hash.Hash)"`);
    lines.push(`"$($hash.Hash)  $(Split-Path ${target} -Leaf)" | Out-File -FilePath "$OutDir.sha256.txt" -Encoding UTF8`);
    lines.push(``);
  }

    lines.push(`Write-Host ""`);
  lines.push(`Write-Host "[+] Collection complete: ${compress ? '$OutDir.zip' : '$OutDir'}"`);
  if (hashFile) lines.push(`Write-Host "[+] SHA256 hash: $OutDir.sha256.txt"`);

  return lines.join('\n');
}

function generateLinuxScript({ caseNum, analyst, artifacts, compress, hashFile }) {
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const lines = [];
  lines.push(`#!/bin/bash`);
  lines.push(`# Heimdall DFIR Collection Agent — Linux`);
  lines.push(`# Case: ${caseNum || 'N/A'} | Analyst: ${analyst || 'N/A'} | Generated: ${new Date().toISOString().slice(0, 16)}`);
  lines.push(`# EXECUTE AS ROOT`);
  lines.push(``);
  lines.push(`OUT_DIR="/tmp/forensic_collect_${date}"`);
  lines.push(`mkdir -p "$OUT_DIR"`);
  lines.push(``);

  if (artifacts.syslog) {
    lines.push(`# System logs`);
    lines.push(`echo "[*] Collecting system logs..."`);
    lines.push(`mkdir -p "$OUT_DIR/logs"`);
    lines.push(`cp -r /var/log/syslog* "$OUT_DIR/logs/" 2>/dev/null`);
    lines.push(`cp -r /var/log/auth.log* "$OUT_DIR/logs/" 2>/dev/null`);
    lines.push(`cp -r /var/log/kern.log* "$OUT_DIR/logs/" 2>/dev/null`);
    lines.push(`cp -r /var/log/messages* "$OUT_DIR/logs/" 2>/dev/null`);
    lines.push(`journalctl --no-pager > "$OUT_DIR/logs/journal.txt" 2>/dev/null`);
    lines.push(``);
  }

  if (artifacts.process) {
    lines.push(`# Process info`);
    lines.push(`echo "[*] Collecting processes..."`);
    lines.push(`ps auxf > "$OUT_DIR/processes.txt"`);
    lines.push(`cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\\0' ' ' > "$OUT_DIR/cmdlines.txt"`);
    lines.push(``);
  }

  if (artifacts.network) {
    lines.push(`# Network`);
    lines.push(`echo "[*] Collecting network data..."`);
    lines.push(`ss -tanup > "$OUT_DIR/network_connections.txt" 2>/dev/null`);
    lines.push(`ip route > "$OUT_DIR/routes.txt" 2>/dev/null`);
    lines.push(`ip addr > "$OUT_DIR/interfaces.txt" 2>/dev/null`);
    lines.push(`iptables -L -n -v > "$OUT_DIR/iptables.txt" 2>/dev/null`);
    lines.push(``);
  }

  if (artifacts.cron) {
    lines.push(`# Crontabs`);
    lines.push(`echo "[*] Collecting crontabs..."`);
    lines.push(`mkdir -p "$OUT_DIR/cron"`);
    lines.push(`crontab -l > "$OUT_DIR/cron/crontab_current_user.txt" 2>/dev/null`);
    lines.push(`ls -la /etc/cron* > "$OUT_DIR/cron/cron_dirs.txt" 2>/dev/null`);
    lines.push(`cat /etc/crontab >> "$OUT_DIR/cron/crontab_system.txt" 2>/dev/null`);
    lines.push(``);
  }

  if (artifacts.persistence) {
    lines.push(`# Persistence`);
    lines.push(`echo "[*] Collecting persistence..."`);
    lines.push(`mkdir -p "$OUT_DIR/persistence"`);
    lines.push(`ls -la /etc/init.d/ > "$OUT_DIR/persistence/init_d.txt" 2>/dev/null`);
    lines.push(`systemctl list-units --type=service > "$OUT_DIR/persistence/systemd_services.txt" 2>/dev/null`);
    lines.push(`cat /etc/rc.local >> "$OUT_DIR/persistence/rc_local.txt" 2>/dev/null`);
    lines.push(``);
  }

  if (artifacts.ram) {
    lines.push(`# RAM`);
    lines.push(`echo "[*] Collecting RAM..."`);
    lines.push(`mkdir -p "$OUT_DIR/ram"`);
    lines.push(`dd if=/dev/mem of="$OUT_DIR/ram/memory.raw" bs=1M 2>/dev/null || echo "[-] /dev/mem non accessible"`);
    lines.push(``);
  }

  if (compress) {
    lines.push(`# Compression`);
    lines.push(`echo "[*] Compressing..."`);
    lines.push(`tar czf "\${OUT_DIR}.tar.gz" "$OUT_DIR" 2>/dev/null`);
    lines.push(``);
  }

  if (hashFile) {
    lines.push(`# SHA-256 Hash`);
    const target = compress ? `"\${OUT_DIR}.tar.gz"` : `"$OUT_DIR"`;
    lines.push(`sha256sum ${target} > "\${OUT_DIR}.sha256"`);
    lines.push(`echo "[+] Hash SHA256: $(cat \${OUT_DIR}.sha256)"`);
    lines.push(``);
  }

  lines.push(`echo "[+] Collection complete: ${compress ? '${OUT_DIR}.tar.gz' : '$OUT_DIR'}"`);

  return lines.join('\n');
}

export default function CollectionAgentPage() {
  const { t } = useTranslation();
  const [os, setOs] = useState('windows');
  const [caseNum, setCaseNum] = useState('');
  const [analyst, setAnalyst] = useState('');
  const [outputDir, setOutputDir] = useState('C:\\ForensicCollect');
  const [artifacts, setArtifacts] = useState({

    evtx: true, prefetch: true, mft: true, registry: true,
    amcache: true, lnk: true, sysmon: true, scheduled_tasks: true,
    ram: false, pcap: false,

    syslog: true, process: true, network: true,
    cron: true, persistence: true,
  });
  const [compress, setCompress] = useState(true);
  const [hashFile, setHashFile] = useState(true);
  const [copied, setCopied] = useState(false);

  const script = useMemo(() => {
    if (os === 'windows') {
      return generateWindowsScript({ caseNum, analyst, outputDir, artifacts, compress, hashFile });
    } else {
      return generateLinuxScript({ caseNum, analyst, artifacts, compress, hashFile });
    }
  }, [os, caseNum, analyst, outputDir, artifacts, compress, hashFile]);

  const toggleArtifact = useCallback((key) => {
    setArtifacts(prev => ({ ...prev, [key]: !prev[key] }));
  }, []);

  const handleDownload = useCallback(() => {
    const ext = os === 'windows' ? 'ps1' : 'sh';
    const filename = `heimdall-collect-${caseNum || 'case'}-${new Date().toISOString().slice(0, 10)}.${ext}`;
    const blob = new Blob([script], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [script, os, caseNum]);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(script);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (_e) {}
  }, [script]);

  const artifactLabels = os === 'windows' ? WIN_ARTIFACT_LABELS : LIN_ARTIFACT_LABELS;

  const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
  const labelStyle = {
    display: 'flex', alignItems: 'center', gap: 8,
    fontSize: 12, color: 'var(--fl-dim)', cursor: 'pointer',
    padding: '3px 0',
  };

  const inputStyle = {
    width: '100%', padding: '6px 10px',
    background: 'var(--fl-input-bg)', color: 'var(--fl-text)',
    border: '1px solid var(--fl-border)', borderRadius: 6,
    fontSize: 12, fontFamily: MONO, outline: 'none',
  };

  const sectionLabel = { fontSize: 9.5, color: 'var(--fl-muted)', fontWeight: 600, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 8 };

  return (
    <div style={{ display: 'flex', height: '100vh', background: 'var(--fl-bg)', overflow: 'hidden' }}>

      <div style={{ width: 300, flexShrink: 0, borderRight: '1px solid var(--fl-border)', overflowY: 'auto', padding: '20px 16px', display: 'flex', flexDirection: 'column', gap: 22 }}>

        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Terminal size={15} style={{ color: 'var(--fl-accent)' }} />
            <span style={{ fontSize: 16, fontWeight: 600, color: 'var(--fl-text)', fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.01em' }}>Agent de collecte</span>
          </div>
          <p style={{ fontSize: 11, color: 'var(--fl-muted)', margin: '4px 0 0', fontFamily: 'var(--f-ui, sans-serif)', lineHeight: 1.45 }}>Forensic collection script generated locally.</p>
        </div>

        <div>
          <div style={sectionLabel}>Target system</div>
          <div style={{ display: 'flex', gap: 8 }}>
            {['windows', 'linux'].map(o => (
              <button
                key={o}
                onClick={() => setOs(o)}
                style={{
                  flex: 1, padding: '6px 0', fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                  border: `1px solid ${os === o ? 'var(--fl-accent)' : 'var(--fl-border)'}`,
                  background: os === o ? 'color-mix(in srgb, var(--fl-accent) 13%, transparent)' : 'transparent',
                  color: os === o ? 'var(--fl-accent)' : 'var(--fl-dim)',
                  borderRadius: 5, cursor: 'pointer', textTransform: 'capitalize',
                }}
              >
                {o === 'windows' ? 'Windows (.ps1)' : 'Linux (.sh)'}
              </button>
            ))}
          </div>
        </div>

        <div>
          <div style={sectionLabel}>Metadata</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--fl-dim)', display: 'block', marginBottom: 3 }}>{t('collection.case_number_label')}</label>
              <input
                value={caseNum}
                onChange={e => setCaseNum(e.target.value)}
                placeholder={t('collection.case_number_ph')}
                style={inputStyle}
              />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--fl-dim)', display: 'block', marginBottom: 3 }}>{t('collection.analyst_label')}</label>
              <input
                value={analyst}
                onChange={e => setAnalyst(e.target.value)}
                placeholder={t('collection.analyst_ph')}
                style={inputStyle}
              />
            </div>
            {os === 'windows' && (
              <div>
                <label style={{ fontSize: 11, color: 'var(--fl-dim)', display: 'block', marginBottom: 3 }}>{t('collection.output_dir_label')}</label>
                <input
                  value={outputDir}
                  onChange={e => setOutputDir(e.target.value)}
                  placeholder={t('collection.output_dir_ph')}
                  style={inputStyle}
                />
              </div>
            )}
          </div>
        </div>

        <div>
          <div style={sectionLabel}>Artifacts to collect</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {Object.entries(artifactLabels).map(([key, label]) => (
              <label key={key} style={labelStyle}>
                <input
                  type="checkbox"
                  checked={!!artifacts[key]}
                  onChange={() => toggleArtifact(key)}
                  style={{ accentColor: 'var(--fl-accent)' }}
                />
                <span style={{ color: artifacts[key] ? 'var(--fl-dim)' : 'var(--fl-muted)' }}>{label}</span>
              </label>
            ))}
          </div>
        </div>

        <div>
          <div style={sectionLabel}>Options</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <label style={labelStyle}>
              <input
                type="checkbox"
                checked={compress}
                onChange={e => setCompress(e.target.checked)}
                style={{ accentColor: 'var(--fl-accent)' }}
              />
              <span>Compresser l'archive ({os === 'windows' ? '.zip' : '.tar.gz'})</span>
            </label>
            <label style={labelStyle}>
              <input
                type="checkbox"
                checked={hashFile}
                onChange={e => setHashFile(e.target.checked)}
                style={{ accentColor: 'var(--fl-accent)' }}
              />
              <span>Calculer SHA-256</span>
            </label>
          </div>
        </div>

        
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <button
            onClick={handleDownload}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
              padding: '9px 0', fontSize: 12, fontFamily: MONO, fontWeight: 600,
              background: 'var(--fl-accent)', color: '#fff', border: '1px solid var(--fl-accent)', borderRadius: 7, cursor: 'pointer',
            }}
          >
            <Download size={13} />
            Download ({os === 'windows' ? '.ps1' : '.sh'})
          </button>
          <button
            onClick={handleCopy}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
              padding: '8px 0', fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
              background: copied ? 'color-mix(in srgb, var(--fl-ok) 13%, transparent)' : 'transparent',
              color: copied ? 'var(--fl-ok)' : 'var(--fl-dim)',
              border: `1px solid ${copied ? 'color-mix(in srgb, var(--fl-ok) 25%, transparent)' : 'var(--fl-border)'}`,
              borderRadius: 6, cursor: 'pointer', transition: 'all 0.2s',
            }}
          >
            {copied ? <CheckCircle size={13} /> : <Copy size={13} />}
            {copied ? 'Copied!' : 'Copy to clipboard'}
          </button>
        </div>

        
        <div style={{ fontSize: 10, color: 'var(--fl-muted)', lineHeight: 1.5, borderTop: '1px solid var(--fl-panel)', paddingTop: 12 }}>
          This script is generated locally in the browser. No data is sent to the server. Always run it with administrator/root privileges on the target machine.
        </div>
      </div>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 16px', borderBottom: '1px solid var(--fl-border)', background: 'var(--fl-panel)', flexShrink: 0 }}>
          <span style={{ width: 7, height: 7, borderRadius: 2, background: 'var(--fl-ok)', flexShrink: 0 }} />
          <span style={{ fontSize: 11.5, fontFamily: MONO, color: 'var(--fl-dim)' }}>
            {os === 'windows' ? 'PowerShell · .ps1' : 'Bash · .sh'}
          </span>
          <span style={{ marginLeft: 'auto', fontSize: 10.5, fontFamily: MONO, color: 'var(--fl-muted)' }}>
            {script.split('\n').length} lines · generated locally
          </span>
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
          <pre style={{
            margin: 0, fontFamily: MONO,
            fontSize: 12, lineHeight: 1.7,
            color: 'var(--fl-text)', whiteSpace: 'pre', tabSize: 2,
          }}>
            {script.split('\n').map((line, i) => {
              let color = 'var(--fl-text)';
              if (line.startsWith('#')) color = 'var(--fl-ok)';
              else if (line.match(/^(Write-Host|echo)\s/)) color = 'var(--fl-dim)';
              else if (line.match(/^(if|else|try|catch|New-Item|Copy-Item|mkdir|cp|ss|ps|cat)\b/)) color = 'var(--fl-accent)';
              else if (line.match(/\$\w+\s*=/)) color = 'var(--fl-gold)';
              return (
                <span key={i} style={{ display: 'block' }}>
                  <span style={{ color: 'var(--fl-subtle)', userSelect: 'none', minWidth: 32, display: 'inline-block', textAlign: 'right', marginRight: 16 }}>
                    {i + 1}
                  </span>
                  <span style={{ color }}>{line || ' '}</span>
                </span>
              );
            })}
          </pre>
        </div>
      </div>
    </div>
  );
}
