'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// Premium forensic report renderer (pdfkit vector engine).
//
// Produces a designed, IR-firm-grade PDF: branded cover, an executive dashboard
// page (threat gauge + KPIs + severity bars + ATT&CK strip), a MITRE heatmap,
// severity-chipped findings, IOC tables, an analyst timeline, and a chain of
// custody — with a running header/footer and page numbers on every page.
//
// All geometry is in PDF points (A4 = 595.28 × 841.89). The document MUST be
// created with `bufferPages: true` so the chrome pass can number every page.
// ─────────────────────────────────────────────────────────────────────────────

const PW = 595.28, PH = 841.89;
const MX = 48;                         // content side margin
const CW = PW - MX * 2;                // content width (~499)
const TOP = 84;                        // content top (below header)
const BOTTOM = 798;                    // content bottom (above footer)

const INK = '#16181D', SUB = '#5B6470', FAINT = '#9AA3AF', HAIR = '#E5E8EC';
const PANEL = '#F6F7F9', PAPER = '#FFFFFF', COVER = '#14151A', COVER2 = '#1E2027';

const SEV = {
  CRITIQUE: '#D7263D', 'ÉLEVÉ': '#E8730C', MOYEN: '#C99A06', FAIBLE: '#2E9E5B',
  critical: '#D7263D', high: '#E8730C', medium: '#C99A06', low: '#2E9E5B', info: '#6B7280',
};
const sevColor = (k) => SEV[k] || SEV[String(k || '').toLowerCase()] || '#6B7280';

const F = 'Helvetica', FB = 'Helvetica-Bold', FI = 'Helvetica-Oblique', FM = 'Courier', FMB = 'Courier-Bold';

const fmtDate = (d) => { try { return new Date(d).toLocaleString('fr-FR', { dateStyle: 'medium', timeStyle: 'short' }); } catch { return '—'; } };
const fmtDay = (d) => { try { return new Date(d).toLocaleDateString('fr-FR', { dateStyle: 'long' }); } catch { return '—'; } };
const short = (s, n) => { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n - 1) + '…' : s; };

// ── Low-level helpers ────────────────────────────────────────────────────────

function ensure(doc, h) {
  if (doc.y + h > BOTTOM) { doc.addPage(); doc.y = TOP; }
}

function chip(doc, x, y, text, color, { fill = true } = {}) {
  doc.font(FB).fontSize(7.5);
  const tw = doc.widthOfString(text);
  const w = tw + 12, h = 14;
  doc.save();
  if (fill) {
    doc.roundedRect(x, y, w, h, 3).fillColor(color).fillOpacity(0.12).fill();
    doc.fillOpacity(1).roundedRect(x, y, w, h, 3).lineWidth(0.7).strokeColor(color).strokeOpacity(0.45).stroke();
  }
  doc.strokeOpacity(1).fillColor(color).text(text, x + 6, y + 3.5, { lineBreak: false });
  doc.restore();
  return w;
}

function sectionTitle(doc, num, title, A) {
  ensure(doc, 46);
  const y = doc.y;
  doc.save();
  doc.roundedRect(MX, y, 22, 22, 4).fillColor(A).fillOpacity(0.12).fill();
  doc.fillOpacity(1).fillColor(A).font(FB).fontSize(11).text(String(num), MX, y + 5.5, { width: 22, align: 'center' });
  doc.fillColor(INK).font(FB).fontSize(14).text(title, MX + 32, y + 3.5, { width: CW - 32, lineBreak: false });
  doc.restore();
  doc.y = y + 30;
  doc.save().moveTo(MX, doc.y).lineTo(MX + CW, doc.y).lineWidth(0.8).strokeColor(HAIR).stroke().restore();
  doc.y += 12;
}

function subLabel(doc, text, color) {
  ensure(doc, 18);
  doc.font(FB).fontSize(8.5).fillColor(color || SUB)
    .text(String(text).toUpperCase(), MX, doc.y, { characterSpacing: 0.6, lineBreak: false });
  doc.y += 14;
}

function para(doc, text, { color = SUB, size = 9.5, x = MX, width = CW, gap = 6 } = {}) {
  if (!text) return;
  ensure(doc, 30);
  doc.font(F).fontSize(size).fillColor(color).text(String(text), x, doc.y, { width, align: 'justify', lineGap: 1.5 });
  doc.y += gap;
}

// AI / highlight callout box.
function callout(doc, title, text, A) {
  if (!text) return;
  doc.font(F).fontSize(9.5);
  const inset = 12;
  const h = doc.heightOfString(String(text), { width: CW - inset * 2 - 4, lineGap: 1.5 }) + 34;
  ensure(doc, h + 8);
  const y = doc.y;
  doc.save();
  doc.roundedRect(MX, y, CW, h, 7).fillColor(A).fillOpacity(0.05).fill();
  doc.fillOpacity(1).roundedRect(MX, y, CW, h, 7).lineWidth(0.8).strokeColor(A).strokeOpacity(0.3).stroke();
  doc.strokeOpacity(1).rect(MX, y + 6, 3, h - 12).fillColor(A).fill();
  doc.fillColor(A).font(FB).fontSize(8).text(String(title).toUpperCase(), MX + inset, y + 11, { characterSpacing: 0.6 });
  doc.fillColor(INK).font(F).fontSize(9.5).text(String(text), MX + inset, y + 24, { width: CW - inset * 2 - 4, lineGap: 1.5, align: 'justify' });
  doc.restore();
  doc.y = y + h + 10;
}

// ── Cover ────────────────────────────────────────────────────────────────────

function drawCover(doc, d, A) {
  doc.rect(0, 0, PW, PH).fill(COVER);
  doc.rect(0, 0, PW, 250).fill(COVER2);
  doc.rect(0, 0, PW, 4).fill(A);   // accent rule top

  // wordmark — `continued` keeps x tracking correct across the colour change + characterSpacing
  doc.font(FB).fontSize(13);
  doc.fillColor('#FFFFFF').text('HEIMDALL', MX, 56, { characterSpacing: 3, continued: true });
  doc.fillColor(A).text(' DFIR', { characterSpacing: 3 });
  doc.fillColor(FAINT).font(FM).fontSize(8).text((d.org || 'Heimdall DFIR'), PW - MX - 240, 60, { width: 240, align: 'right', lineBreak: false });

  // classification banner
  const cls = (d.classification || 'CONFIDENTIEL').toUpperCase();
  doc.font(FB).fontSize(8);
  const cw = doc.widthOfString(cls) + 18;
  doc.roundedRect(MX, 300, cw, 18, 3).fillColor(SEV.CRITIQUE).fillOpacity(0.18).fill();
  doc.fillOpacity(1).fillColor('#FF8A95').font(FB).fontSize(8).text(cls, MX + 9, 304.5, { lineBreak: false });

  // title — measured so everything below it is placed without collisions
  const TY = 332;
  const title = short(d.caseData.title || 'Investigation', 84);
  doc.font(FB).fontSize(27);
  const titleH = doc.heightOfString(title, { width: CW, lineGap: 2 });
  doc.fillColor('#FFFFFF').text(title, MX, TY, { width: CW, lineGap: 2 });
  let y = TY + titleH + 10;
  doc.fillColor(A).font(FMB).fontSize(13).text(d.caseData.case_number || '', MX, y, { lineBreak: false });
  y += 20;
  doc.fillColor(FAINT).font(F).fontSize(11).text("Rapport d'analyse forensique numérique", MX, y, { lineBreak: false });
  y += 28;

  // severity ribbon
  const pr = d.caseData.priority || 'MOYEN';
  const prC = sevColor(pr);
  doc.roundedRect(MX, y, 150, 42, 6).fillColor(prC).fillOpacity(0.16).fill();
  doc.fillOpacity(1).fillColor(prC).font(FB).fontSize(8).text('PRIORITÉ', MX + 12, y + 9, { characterSpacing: 0.8, lineBreak: false });
  doc.fillColor('#FFFFFF').font(FB).fontSize(15).text(String(pr).toUpperCase(), MX + 12, y + 21, { lineBreak: false });

  // metadata grid (fixed lower band so it never collides with a tall title)
  const meta = [
    ['Investigateur', d.caseData.investigator_name || 'Non assigné'],
    ['Statut', String(d.caseData.status || '—').toUpperCase()],
    ['Ouvert le', fmtDay(d.caseData.opened_at || d.caseData.created_at)],
    ['Preuves analysées', String((d.evidence || []).length)],
    ['Indicateurs (IOC)', String((d.iocs || []).length)],
    ['Techniques ATT&CK', String((d.mitre || []).length)],
  ];
  const my = 632;
  for (let i = 0; i < meta.length; i++) {
    const col = i % 2, row = Math.floor(i / 2);
    const x = MX + col * (CW / 2), yy = my + row * 50;
    doc.fillColor(FAINT).font(FM).fontSize(7.5).text(meta[i][0].toUpperCase(), x, yy, { characterSpacing: 0.5, lineBreak: false });
    doc.fillColor('#FFFFFF').font(FB).fontSize(12).text(short(meta[i][1], 38), x, yy + 12, { width: CW / 2 - 20, lineBreak: false });
  }

  // bottom bar
  doc.rect(0, PH - 60, PW, 60).fill(COVER2);
  doc.rect(0, PH - 60, PW, 2).fill(A);
  const reportId = `HD-${(d.caseData.case_number || 'CASE').replace(/[^A-Za-z0-9]/g, '')}-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}`;
  doc.fillColor(FAINT).font(FM).fontSize(8).text(`RAPPORT ${reportId}`, MX, PH - 42, { lineBreak: false });
  doc.fillColor(FAINT).font(FM).fontSize(8).text(`${fmtDate(new Date())}  ·  ${d.generatedBy || ''}`, PW - MX - 280, PH - 42, { width: 280, align: 'right', lineBreak: false });
  if (d.aiNarrative) {
    doc.rect(MX, PH - 24, 5, 5).fill(A);
    doc.fillColor(A).font(FB).fontSize(7).text('ENRICHI PAR ANALYSE IA', MX + 9, PH - 26, { characterSpacing: 0.6, lineBreak: false });
  }
}

// ── Executive dashboard ──────────────────────────────────────────────────────

function drawGauge(doc, cx, cy, r, pct, color) {
  const a0 = Math.PI * 0.75, a1 = Math.PI * 2.25, span = a1 - a0;
  const steps = 64;
  const pt = (a) => [cx + Math.cos(a) * r, cy + Math.sin(a) * r];
  doc.save().lineWidth(9).lineCap('round');
  // track
  doc.strokeColor(HAIR);
  for (let i = 0; i < steps; i++) {
    const [x1, y1] = pt(a0 + span * (i / steps)), [x2, y2] = pt(a0 + span * ((i + 1) / steps));
    doc.moveTo(x1, y1).lineTo(x2, y2).stroke();
  }
  // value
  const vs = Math.max(0, Math.round(steps * (pct / 100)));
  doc.strokeColor(color);
  for (let i = 0; i < vs; i++) {
    const [x1, y1] = pt(a0 + span * (i / steps)), [x2, y2] = pt(a0 + span * ((i + 1) / steps));
    doc.moveTo(x1, y1).lineTo(x2, y2).stroke();
  }
  doc.restore();
  doc.fillColor(INK).font(FB).fontSize(26).text(String(Math.round(pct)), cx - 40, cy - 16, { width: 80, align: 'center', lineBreak: false });
  doc.fillColor(FAINT).font(FM).fontSize(7.5).text('/ 100', cx - 40, cy + 13, { width: 80, align: 'center', lineBreak: false });
}

function kpiTile(doc, x, y, w, label, value, color) {
  const h = 56;
  doc.save();
  doc.roundedRect(x, y, w, h, 6).fillColor(PANEL).fill();
  doc.roundedRect(x, y, w, h, 6).lineWidth(0.8).strokeColor(HAIR).stroke();
  doc.rect(x, y + 8, 3, h - 16).fillColor(color || INK).fill();
  doc.fillColor(FAINT).font(FM).fontSize(7).text(String(label).toUpperCase(), x + 12, y + 10, { width: w - 18, characterSpacing: 0.4, lineBreak: false });
  doc.fillColor(color || INK).font(FB).fontSize(22).text(String(value), x + 12, y + 22, { width: w - 18, lineBreak: false });
  doc.restore();
}

function severityBars(doc, x, y, w, counts) {
  const order = ['CRITIQUE', 'ÉLEVÉ', 'MOYEN', 'FAIBLE'];
  const max = Math.max(1, ...order.map(k => counts[k] || 0));
  let yy = y;
  for (const k of order) {
    const n = counts[k] || 0, c = sevColor(k);
    doc.fillColor(SUB).font(F).fontSize(8.5).text(k, x, yy + 1, { width: 60, lineBreak: false });
    const bx = x + 66, bw = w - 66 - 28;
    doc.roundedRect(bx, yy, bw, 9, 2).fillColor(HAIR).fill();
    const fw = Math.max(n > 0 ? 5 : 0, bw * (n / max));
    if (fw > 0) doc.roundedRect(bx, yy, fw, 9, 2).fillColor(c).fill();
    doc.fillColor(INK).font(FB).fontSize(9).text(String(n), bx + bw + 6, yy, { width: 22, align: 'right', lineBreak: false });
    yy += 18;
  }
  return yy;
}

function drawExecutive(doc, d, A) {
  doc.addPage(); doc.y = TOP;
  sectionTitle(doc, 1, 'Synthèse exécutive', A);

  // aggregate counts
  const counts = { CRITIQUE: 0, 'ÉLEVÉ': 0, MOYEN: 0, FAIBLE: 0 };
  for (const h of (d.hayabusa || [])) { if (h.level === 'critical') counts.CRITIQUE++; else if (h.level === 'high') counts['ÉLEVÉ']++; }
  for (const sgm of (d.sigma || [])) { const sv = String(sgm.severity || '').toLowerCase(); if (sv === 'critical') counts.CRITIQUE++; else if (sv === 'high') counts['ÉLEVÉ']++; else if (sv === 'medium') counts.MOYEN++; else counts.FAIBLE++; }
  for (const i of (d.iocs || [])) { if (!i.is_malicious) continue; const s = Number(i.severity) || 0; if (s >= 9) counts.CRITIQUE++; else if (s >= 7) counts['ÉLEVÉ']++; else if (s >= 4) counts.MOYEN++; else counts.FAIBLE++; }

  const malIocs = (d.iocs || []).filter(i => i.is_malicious).length;
  const totalFindings = Object.values(counts).reduce((a, b) => a + b, 0);

  // threat score: priority base + findings weight
  const prBase = { CRITIQUE: 80, 'ÉLEVÉ': 60, MOYEN: 38, FAIBLE: 18 }[d.caseData.priority] ?? 40;
  let score = prBase + counts.CRITIQUE * 6 + counts['ÉLEVÉ'] * 3 + counts.MOYEN * 1;
  score = Math.max(0, Math.min(100, score));
  const level = score >= 75 ? 'ÉLEVÉ' : score >= 45 ? 'MODÉRÉ' : 'FAIBLE';
  const levelC = score >= 75 ? SEV.CRITIQUE : score >= 45 ? SEV.MOYEN : SEV.FAIBLE;

  // top band: gauge (left) + KPIs (right)
  const bandY = doc.y;
  doc.save();
  doc.roundedRect(MX, bandY, 168, 150, 7).fillColor(PANEL).fill().lineWidth(0.8).strokeColor(HAIR).stroke();
  doc.restore();
  drawGauge(doc, MX + 84, bandY + 70, 48, score, levelC);
  doc.fillColor(FAINT).font(FM).fontSize(7.5).text('NIVEAU DE MENACE', MX, bandY + 122, { width: 168, align: 'center', characterSpacing: 0.5 });
  doc.fillColor(levelC).font(FB).fontSize(11).text(level, MX, bandY + 132, { width: 168, align: 'center', lineBreak: false });

  // KPI tiles 2×2 to the right
  const kx = MX + 184, kw = (CW - 184 - 12) / 2;
  kpiTile(doc, kx, bandY, kw, 'Preuves analysées', (d.evidence || []).length, INK);
  kpiTile(doc, kx + kw + 12, bandY, kw, 'IOC malveillants', malIocs, malIocs > 0 ? SEV.CRITIQUE : INK);
  kpiTile(doc, kx, bandY + 68, kw, 'Techniques ATT&CK', (d.mitre || []).length, A);
  kpiTile(doc, kx + kw + 12, bandY + 68, kw, 'Détections', totalFindings, totalFindings > 0 ? SEV['ÉLEVÉ'] : INK);
  doc.y = bandY + 150 + 18;

  // severity distribution
  subLabel(doc, 'Distribution par sévérité', SUB);
  ensure(doc, 80);
  doc.y = severityBars(doc, MX, doc.y, CW, counts) + 8;

  // ATT&CK tactic coverage strip
  const tactics = [...new Set((d.mitre || []).map(m => m.tactic).filter(Boolean))];
  if (tactics.length) {
    subLabel(doc, `Couverture ATT&CK · ${tactics.length} tactique(s)`, SUB);
    ensure(doc, 24);
    let cx = MX, cy = doc.y;
    for (const tac of tactics) {
      doc.font(FB).fontSize(7.5);
      const w = doc.widthOfString(tac) + 12;
      if (cx + w > MX + CW) { cx = MX; cy += 20; }
      chip(doc, cx, cy, tac, A);
      cx += w + 6;
    }
    doc.y = cy + 26;
  }

  // AI executive summary (the rest of the AI narrative lives in the dedicated "Analyse IA" section)
  if (d.aiNarrative?.executive_summary) callout(doc, 'Synthèse exécutive — IA', d.aiNarrative.executive_summary, A);
}

// ── Generic styled table ─────────────────────────────────────────────────────

function table(doc, cols, rows, { rowH = 18, headerColor } = {}) {
  const total = cols.reduce((a, c) => a + c.w, 0);
  // header
  ensure(doc, rowH + 4);
  let y = doc.y;
  doc.save();
  doc.rect(MX, y, total, rowH).fillColor(headerColor || INK).fillOpacity(0.04).fill();
  doc.fillOpacity(1);
  let x = MX;
  for (const c of cols) {
    doc.fillColor(SUB).font(FB).fontSize(7.5).text(c.label.toUpperCase(), x + 6, y + 5.5, { width: c.w - 10, align: c.align || 'left', characterSpacing: 0.4, lineBreak: false });
    x += c.w;
  }
  doc.restore();
  doc.y = y + rowH;
  // rows
  rows.forEach((r, i) => {
    ensure(doc, rowH);
    y = doc.y;
    if (i % 2 === 0) { doc.save().rect(MX, y, total, rowH).fillColor(PANEL).fillOpacity(0.6).fill().restore(); }
    x = MX;
    for (const c of cols) {
      const cell = r[c.key];
      if (typeof cell === 'function') { cell(doc, x, y, c.w, rowH); }
      else {
        const fs = c.size || 8.5;
        doc.fillColor(c.color || INK).font(c.mono ? FM : F).fontSize(fs)
          .text(short(cell, c.max || 80), x + 6, y + 5.5, { width: c.w - 10, align: c.align || 'left', lineBreak: false, ellipsis: true, height: fs + 4 });
      }
      x += c.w;
    }
    doc.save().moveTo(MX, y + rowH).lineTo(MX + total, y + rowH).lineWidth(0.5).strokeColor(HAIR).stroke().restore();
    doc.y = y + rowH;
  });
  doc.y += 8;
}

// ── MITRE ────────────────────────────────────────────────────────────────────

function drawMitre(doc, d, num, A) {
  const rows = d.mitre || [];
  if (!rows.length) return false;
  doc.addPage(); doc.y = TOP;
  sectionTitle(doc, num, 'Techniques MITRE ATT&CK', A);

  // group by tactic
  const byTac = {};
  for (const r of rows) { (byTac[r.tactic || 'Autre'] ||= []).push(r); }
  const tileW = (CW - 12) / 3, tileH = 30;
  for (const [tac, techs] of Object.entries(byTac)) {
    ensure(doc, 18 + tileH + 8);   // keep the tactic label with at least its first row of tiles
    subLabel(doc, tac, A);
    let rowY = doc.y;
    techs.forEach((tch, i) => {
      const col = i % 3;
      if (col === 0) {
        if (rowY + tileH > BOTTOM) { doc.addPage(); doc.y = TOP; rowY = TOP; }
      }
      const x = MX + col * (tileW + 6);
      doc.save();
      doc.roundedRect(x, rowY, tileW, tileH, 4).fillColor(A).fillOpacity(0.06).fill();
      doc.fillOpacity(1).roundedRect(x, rowY, tileW, tileH, 4).lineWidth(0.7).strokeColor(A).strokeOpacity(0.3).stroke();
      doc.strokeOpacity(1).fillColor(A).font(FMB).fontSize(8).text(tch.technique_id || '—', x + 8, rowY + 6, { lineBreak: false });
      doc.fillColor(SUB).font(F).fontSize(7).text(short(tch.technique_name || tch.technique || '', 34), x + 8, rowY + 17, { width: tileW - 14, lineBreak: false });
      doc.restore();
      if (col === 2 || i === techs.length - 1) rowY += tileH + 6;
    });
    doc.y = rowY + 8;
  }
  return true;
}

// ── Findings (Hayabusa + Sigma + YARA) ───────────────────────────────────────

function drawFindings(doc, d, num, A) {
  const hay = d.hayabusa || [], sigma = d.sigma || [], yara = d.yara || [];
  if (!hay.length && !sigma.length && !yara.length) return false;
  doc.addPage(); doc.y = TOP;
  sectionTitle(doc, num, 'Détections & alertes', A);

  if (hay.length) {
    subLabel(doc, `Hayabusa · Sigma EVTX (${hay.length})`, SEV.CRITIQUE);
    for (const h of hay) {
      ensure(doc, 30);
      const c = sevColor(h.level);
      const y = doc.y;
      doc.save().rect(MX, y + 2, 3, 22).fillColor(c).fill().restore();
      chip(doc, MX + 10, y, String(h.level || '').toUpperCase(), c);
      doc.fillColor(INK).font(FB).fontSize(9).text(short(h.rule_title || h.description || 'Détection', 70), MX + 10 + 56, y + 1, { width: CW - 66, lineBreak: false });
      doc.fillColor(FAINT).font(FM).fontSize(7.5).text(`${h.timestamp ? fmtDate(h.timestamp) : ''}${h.host_name ? '  ·  ' + h.host_name : ''}${h.tactics ? '  ·  ' + short(h.tactics, 40) : ''}`, MX + 10 + 56, y + 14, { width: CW - 66, lineBreak: false });
      doc.y = y + 28;
    }
    doc.y += 6;
  }

  if (sigma.length) {
    subLabel(doc, `Sigma Threat Hunting (${sigma.length})`, A);
    table(doc, [
      { key: 'rule', label: 'Règle', w: 240, mono: false, max: 52 },
      { key: 'sev', label: 'Sévérité', w: 90 },
      { key: 'n', label: 'Matches', w: CW - 240 - 90, align: 'right', mono: true },
    ], sigma.map(s => ({
      rule: s.rule_name,
      sev: (doc, x, y, w) => { chip(doc, x + 6, y + 3, String(s.severity || 'info').toUpperCase(), sevColor(s.severity)); },
      n: String(s.match_count || 0),
    })));
  }

  if (yara.length) {
    subLabel(doc, `Correspondances YARA (${yara.length})`, SEV['ÉLEVÉ']);
    table(doc, [
      { key: 'rule', label: 'Règle', w: 230, max: 50 },
      { key: 'ev', label: 'Preuve', w: 180, color: SUB, max: 38 },
      { key: 'n', label: 'Chaînes', w: CW - 230 - 180, align: 'right', mono: true },
    ], yara.slice(0, 60).map(y => ({ rule: y.rule_name, ev: y.evidence_name || '—', n: String(y.match_count || 0) })));
  }
  return true;
}

// ── IOCs ─────────────────────────────────────────────────────────────────────

function drawIocs(doc, d, num, A) {
  const iocs = d.iocs || [];
  if (!iocs.length) return false;
  doc.addPage(); doc.y = TOP;
  sectionTitle(doc, num, 'Indicateurs de compromission', A);

  table(doc, [
    { key: 'type', label: 'Type', w: 70, mono: true, color: A, size: 8 },
    { key: 'value', label: 'Valeur', w: 300, mono: true, size: 8, max: 64 },
    { key: 'verdict', label: 'Verdict', w: CW - 70 - 300 },
  ], iocs.map(i => ({
    type: String(i.ioc_type || i.type || '—').toUpperCase(),
    value: i.value,
    verdict: (doc, x, y, w) => {
      const mal = i.is_malicious;
      chip(doc, x + 6, y + 3, mal ? 'MALVEILLANT' : 'SUSPECT', mal ? SEV.CRITIQUE : SEV.MOYEN);
    },
  })), { rowH: 19 });
  return true;
}

// ── Analyst timeline ─────────────────────────────────────────────────────────

function drawTimeline(doc, d, num, A) {
  const bm = d.bookmarks || [], pins = d.pins || [], notes = d.notes || [];
  const total = bm.length + pins.length + notes.length;
  doc.addPage(); doc.y = TOP;
  sectionTitle(doc, num, `Chronologie de l'analyste (${total})`, A);

  if (total === 0) { para(doc, "Aucun événement repéré (bookmark, épingle ou note) pour ce cas.", { color: FAINT }); return true; }

  const items = [
    ...bm.map(b => ({ t: b.event_time, title: b.title, desc: b.description, tac: b.mitre_tactic, tech: b.mitre_technique, who: b.author, kind: 'Bookmark', c: b.color || A })),
    ...pins.map(p => ({ t: p.event_time, title: p.title, desc: p.description, tac: null, tech: p.source, who: p.author, kind: 'Épingle', c: SEV['ÉLEVÉ'] })),
    ...notes.map(n => ({ t: n.created_at, title: n.note, desc: null, tac: null, tech: null, who: n.author, kind: 'Note', c: SEV.MOYEN })),
  ].sort((a, b) => new Date(a.t || 0) - new Date(b.t || 0));

  const railX = MX + 4, tx = railX + 14;
  for (const it of items) {
    const hasDesc = !!it.desc, hasWho = !!it.who;
    const ih = 26 + (hasDesc ? 12 : 0) + (hasWho ? 10 : 0);
    ensure(doc, ih);
    const y = doc.y;
    doc.save();
    doc.moveTo(railX, y + 2).lineTo(railX, y + ih - 2).lineWidth(1).strokeColor(HAIR).stroke();
    doc.circle(railX, y + 6, 3.2).fillColor(it.c).fill();
    doc.restore();
    doc.fillColor(FAINT).font(FM).fontSize(7.5).text(it.t ? fmtDate(it.t) : '—', tx, y + 1, { width: 130, lineBreak: false });
    chip(doc, tx + 136, y - 1, it.kind.toUpperCase(), it.c);
    if (it.tech) doc.fillColor(A).font(FMB).fontSize(7.5).text(short(it.tech, 16), tx + 202, y + 1, { lineBreak: false });
    doc.fillColor(INK).font(FB).fontSize(9).text(short(it.title || '', 92), tx, y + 14, { width: CW - 20, lineBreak: false });
    let yy = y + 26;
    if (hasDesc) { doc.fillColor(SUB).font(F).fontSize(8).text(short(it.desc, 112), tx, yy, { width: CW - 20, lineBreak: false }); yy += 12; }
    if (hasWho) { doc.fillColor(FAINT).font(FI).fontSize(7).text(`— ${it.who}`, tx, yy, { lineBreak: false }); }
    doc.y = y + ih;
  }
  return true;
}

// ── Evidence + chain of custody ──────────────────────────────────────────────

function drawEvidence(doc, d, num, A) {
  const ev = d.evidence || [];
  doc.addPage(); doc.y = TOP;
  sectionTitle(doc, num, 'Preuves & chaîne de custody', A);
  para(doc, `${ev.length} preuve(s) collectée(s), dont ${ev.filter(e => e.is_highlighted).length} mise(s) en évidence. Intégrité vérifiée par empreintes cryptographiques.`, { color: SUB });
  doc.y += 4;

  for (const e of ev) {
    ensure(doc, 64);
    const y = doc.y;
    doc.save();
    doc.roundedRect(MX, y, CW, 58, 6).fillColor(PANEL).fill().lineWidth(0.8).strokeColor(HAIR).stroke();
    if (e.is_highlighted) doc.rect(MX, y + 6, 3, 46).fillColor(SEV['ÉLEVÉ']).fill();
    doc.fillColor(INK).font(FB).fontSize(10).text(short(e.name, 56), MX + 14, y + 9, { width: CW - 180, lineBreak: false });
    chip(doc, MX + CW - 150, y + 9, String(e.evidence_type || '—').toUpperCase(), A);
    if (e.is_highlighted) chip(doc, MX + CW - 66, y + 9, 'CLÉ', SEV['ÉLEVÉ']);
    const hsh = (lbl, v) => `${lbl} ${v || '—'}`;
    doc.fillColor(SUB).font(FM).fontSize(6.8);
    doc.text(hsh('SHA256', e.hash_sha256), MX + 14, y + 27, { width: CW - 28, lineBreak: false });
    doc.text(`${hsh('MD5', e.hash_md5)}     ${hsh('SHA1', e.hash_sha1)}`, MX + 14, y + 37, { width: CW - 28, lineBreak: false });
    doc.fillColor(FAINT).font(FM).fontSize(6.8).text(`Ajouté ${fmtDate(e.created_at)}   ·   `, MX + 14, y + 47, { continued: true });
    doc.fillColor(SEV.FAIBLE).text('Intégrité vérifiée', { lineBreak: false });
    doc.restore();
    doc.y = y + 64;
  }
  return true;
}

// ── Consolidated AI analysis (ties every AI-generated part together) ─────────

function drawAiAnalysis(doc, d, num, A) {
  const ai = d.aiNarrative;
  if (!ai) return false;
  const parts = [
    ['Découvertes principales', ai.key_findings],
    ['Analyse des indicateurs (IOC)', ai.ioc_analysis],
    ["Techniques & chaîne d'attaque (ATT&CK)", ai.mitre_analysis],
    ['Déroulé chronologique', ai.timeline_narrative],
  ].filter(([, txt]) => txt && String(txt).trim());
  if (!parts.length) return false;
  doc.addPage(); doc.y = TOP;
  sectionTitle(doc, num, "Analyse de l'incident — IA", A);
  para(doc, "Analyse rédigée automatiquement à partir des artefacts, détections, IOCs et événements repérés du dossier.", { color: FAINT, size: 8.5 });
  doc.y += 6;
  for (const [label, txt] of parts) {
    ensure(doc, 40);
    // accent tick + label, then justified body
    const ly = doc.y;
    doc.save().rect(MX, ly + 1, 3, 9).fillColor(A).fill().restore();
    doc.font(FB).fontSize(8.5).fillColor(A).text(String(label).toUpperCase(), MX + 9, ly, { characterSpacing: 0.5, lineBreak: false });
    doc.y = ly + 15;
    para(doc, txt, { color: INK, size: 9.5, gap: 14 });
  }
  return true;
}

// ── Analyst free-text notes (explicit — never shown by default) ──────────────

function drawNotes(doc, d, num, A) {
  const raw = d.analystNotes;
  let items = [];
  if (typeof raw === 'string') { if (raw.trim()) items = [{ title: null, text: raw.trim() }]; }
  else if (Array.isArray(raw)) {
    items = raw
      .map(x => typeof x === 'string' ? { title: null, text: x } : { title: x && x.title, text: x && (x.text || x.note) })
      .filter(x => x.text && String(x.text).trim());
  }
  if (!items.length) return false;
  doc.addPage(); doc.y = TOP;
  sectionTitle(doc, num, "Note de l'analyste", A);
  for (const it of items) callout(doc, it.title || "Commentaire de l'analyste", it.text, A);
  return true;
}

// ── Running header / footer (chrome pass over buffered pages) ─────────────────

function addChrome(doc, d, A) {
  const range = doc.bufferedPageRange();
  const cls = (d.classification || 'CONFIDENTIEL').toUpperCase();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    if (i === range.start) continue; // skip cover
    const n = i - range.start + 1, totalNoCover = range.count - 1, pageNo = i - range.start; // cover is page 0
    doc.save();
    // header
    doc.rect(0, 0, PW, 2).fillColor(A).fillOpacity(0.5).fill().fillOpacity(1);
    doc.fillColor(FAINT).font(FB).fontSize(7).text('HEIMDALL DFIR', MX, 22, { characterSpacing: 1, lineBreak: false });
    doc.fillColor(FAINT).font(FM).fontSize(7).text(cls, 0, 22, { width: PW, align: 'center', lineBreak: false });
    doc.fillColor(FAINT).font(FM).fontSize(7).text(d.caseData.case_number || '', PW - MX - 160, 22, { width: 160, align: 'right', lineBreak: false });
    doc.moveTo(MX, 36).lineTo(PW - MX, 36).lineWidth(0.6).strokeColor(HAIR).stroke();
    // footer
    doc.moveTo(MX, PH - 34).lineTo(PW - MX, PH - 34).lineWidth(0.6).strokeColor(HAIR).stroke();
    doc.fillColor(FAINT).font(FM).fontSize(7).text(d.footerText || d.org || 'Heimdall DFIR', MX, PH - 26, { width: 280, lineBreak: false });
    doc.fillColor(FAINT).font(FM).fontSize(7).text(`Page ${pageNo} / ${totalNoCover}`, PW - MX - 120, PH - 26, { width: 120, align: 'right', lineBreak: false });
    doc.restore();
    void n;
  }
}

// ── Kill chain (ATT&CK phases, weighted coverage, blind spots) ───────────────

function drawKillChain(doc, d, num, A) {
  const { TACTICS, weightedCoverage, blindSpots } = require('./killChain');
  const f = (d.bookmarks || []).filter((b) => b.mitre_tactic);
  if (!f.length) return false;
  doc.addPage(); doc.y = TOP;
  const cov = weightedCoverage(f);
  sectionTitle(doc, num, 'Kill Chain ATT&CK', A);
  para(doc, `${cov.covered}/${cov.total} tactiques couvertes par les éléments analysés, présentées dans l'ordre du cycle d'attaque MITRE ATT&CK.`, { color: SUB });
  doc.y += 2;

  const confColor = (c) => ({ high: SEV.FAIBLE, medium: SEV.MOYEN, low: FAINT }[String(c || '')] || FAINT);

  for (const tac of TACTICS) {
    const items = f.filter((x) => x.mitre_tactic === tac);
    if (!items.length) continue;
    subLabel(doc, tac, A);
    for (const it of items) {
      const hasSig = !!it.significance;
      ensure(doc, hasSig ? 26 : 16);
      const y = doc.y;
      doc.save().circle(MX + 4, y + 5, 2.6).fillColor(it.color || A).fill().restore();
      doc.fillColor(INK).font(FB).fontSize(9).text(short(it.title || '', 78), MX + 14, y, { width: CW - 160, lineBreak: false });
      if (it.confidence) chip(doc, MX + CW - 70, y - 2, String(it.confidence).toUpperCase(), confColor(it.confidence));
      let yy = y + 12;
      if (it.mitre_technique) { doc.fillColor(A).font(FMB).fontSize(7.5).text(it.mitre_technique, MX + 14, yy, { lineBreak: false }); }
      if (hasSig) { doc.fillColor(SUB).font(FI).fontSize(8).text(short(it.significance, 108), MX + (it.mitre_technique ? 72 : 14), yy, { width: CW - 90, lineBreak: false }); }
      doc.y = y + (hasSig ? 24 : 14);
    }
    doc.y += 4;
  }

  const gaps = blindSpots(f);
  if (gaps.length) {
    doc.y += 4;
    subLabel(doc, 'Zones aveugles — aucun élément', SEV['ÉLEVÉ']);
    para(doc, gaps.join('   ·   '), { color: FAINT, size: 8.5 });
  }
  return true;
}

// ── Investigation workflow (phases + tasks) ──────────────────────────────────

function drawWorkflow(doc, d, num, A) {
  const steps = d.steps || [];
  if (!steps.length) return false;
  doc.addPage(); doc.y = TOP;
  sectionTitle(doc, num, "Avancement de l'investigation", A);
  const done = steps.filter((s) => s.status === 'done').length;
  para(doc, `${done}/${steps.length} étape(s) terminée(s).`, { color: SUB });
  doc.y += 2;

  const STATUS_COLOR = { todo: FAINT, doing: SEV.MOYEN, done: SEV.FAIBLE, blocked: SEV.CRITIQUE };
  const PHASE_LABEL = { acquisition: 'Acquisition', examination: 'Examen technique', analysis: 'Analyse & corrélation', reporting: 'Rédaction du rapport' };
  let curPhase = null;
  for (const s of steps) {
    if (s.phase !== curPhase) { curPhase = s.phase; subLabel(doc, PHASE_LABEL[s.phase] || s.phase, A); }
    ensure(doc, 16);
    const y = doc.y;
    chip(doc, MX, y, String(s.status || 'todo').toUpperCase(), STATUS_COLOR[s.status] || FAINT);
    doc.fillColor(INK).font(F).fontSize(9).text(short(s.title || '', 96), MX + 84, y + 2.5, { width: CW - 96, lineBreak: false });
    doc.y = y + 16;
  }
  return true;
}

// ── Entry point ──────────────────────────────────────────────────────────────

function renderReport(doc, d) {
  const A = (d.accentColor && /^#([0-9a-f]{6})$/i.test(d.accentColor) && d.accentColor.toLowerCase() !== '#00d4ff') ? d.accentColor : '#6E56CF';
  const sec = d.activeSections || new Set();

  drawCover(doc, d, A);
  drawExecutive(doc, d, A);

  let n = 2;
  if (drawAiAnalysis(doc, d, n, A)) n++;   // consolidated AI narrative — ties every generated part together
  if (drawNotes(doc, d, n, A)) n++;        // explicit analyst notes — printed "on top", not gated by sections
  if (sec.has('mitre') && drawMitre(doc, d, n, A)) n++;
  if (sec.has('killchain') && drawKillChain(doc, d, n, A)) n++;
  if (sec.has('workflow') && drawWorkflow(doc, d, n, A)) n++;
  if ((sec.has('hayabusa') || sec.has('sigma') || sec.has('yara')) && drawFindings(doc, d, n, A)) n++;
  if (sec.has('iocs') && drawIocs(doc, d, n, A)) n++;
  if (sec.has('timeline') && drawTimeline(doc, d, n, A)) n++;
  if (sec.has('evidence') || sec.has('custody')) { if (drawEvidence(doc, d, n, A)) n++; }

  if (d.aiNarrative?.recommendations) {
    doc.addPage(); doc.y = TOP;
    sectionTitle(doc, n, 'Recommandations', A);
    callout(doc, 'Remédiation recommandée — IA', d.aiNarrative.recommendations, A);
  }

  addChrome(doc, d, A);
}

module.exports = { renderReport };
