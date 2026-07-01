import { useState, useEffect } from 'react';
import { ShieldCheck, ShieldOff, Plus, Trash2, RefreshCw, Loader2, Check, X } from 'lucide-react';
import { settingsAPI, threatIntelAPI, mispAPI } from '../../utils/api';
import { MONO, UI, SectionHead, Btn, Input, Skeletons, Msg } from './shared';
import { useTranslation } from 'react-i18next';

const SERVICES = ['virustotal', 'abuseipdb', 'shodan', 'greynoise', 'urlhaus', 'malwarebazaar', 'hibp'];

/* ── API-key based services (VirusTotal / AbuseIPDB / Shodan) ───────────── */
function ApiKeys() {
  const { t } = useTranslation();
  const [state, setState]   = useState(null);
  const [drafts, setDrafts] = useState({});
  const [saving, setSaving] = useState(false);
  const [msg, setMsg]       = useState('');

  const load = () => settingsAPI.getIntegrations().then(r => setState(r.data)).catch(() => setState({}));
  useEffect(() => { load(); }, []);

  const save = async () => {
    const patch = {};
    for (const [k, v] of Object.entries(drafts)) if (v !== undefined) patch[k] = v;
    if (Object.keys(patch).length === 0) return;
    setSaving(true); setMsg('');
    try { await settingsAPI.setIntegrations(patch); setDrafts({}); setMsg(t('settings.messages.saved')); load(); }
    catch (e) { setMsg(`✗ ${e.response?.data?.error || t('common.error')}`); }
    finally { setSaving(false); }
  };

  if (!state) return <Skeletons n={3} />;
  return (
    <div style={{ marginTop: 8 }}>
      {SERVICES.map((key, i) => {
        const st = state[key] || {};
        return (
          <div key={key} style={{ display: 'flex', alignItems: 'flex-start', gap: 24, padding: '16px 0', borderBottom: i < SERVICES.length - 1 ? '1px solid var(--fl-border2)' : 'none' }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 13, color: 'var(--fl-text)', fontFamily: UI, fontWeight: 500 }}>{t(`settings.integrations.services.${key}.label`)}</span>
                {st.configured ? (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 9.5, fontFamily: MONO, padding: '1px 7px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-ok) 9%, transparent)', color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 19%, transparent)' }}>
                    <ShieldCheck size={10} /> {t('settings.integrations.configured')} {st.source === 'env' ? '(.env)' : st.last4 ? `(…${st.last4})` : ''}
                  </span>
                ) : (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 9.5, fontFamily: MONO, padding: '1px 7px', borderRadius: 4, background: 'var(--fl-card)', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)' }}>
                    <ShieldOff size={10} /> {t('settings.integrations.missing')}
                  </span>
                )}
              </div>
              <div style={{ fontSize: 11.5, color: 'var(--fl-muted)', fontFamily: UI, marginTop: 3 }}>{t(`settings.integrations.services.${key}.desc`)}</div>
            </div>
            <Input type="password" placeholder={st.source === 'env' ? t('settings.integrations.env_defined') : st.configured ? t('settings.integrations.replace_key') : t('settings.integrations.paste_key')}
              value={drafts[key] ?? ''} onChange={e => setDrafts(d => ({ ...d, [key]: e.target.value }))}
              disabled={st.source === 'env'} width={260} style={{ opacity: st.source === 'env' ? 0.5 : 1 }} />
          </div>
        );
      })}
      <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
        <Btn variant="primary" onClick={save} disabled={saving || Object.keys(drafts).length === 0}>
          {saving ? t('settings.messages.saving') : t('settings.integrations.save_keys')}
        </Btn>
        <Msg msg={msg} />
      </div>
      <p style={{ fontSize: 10.5, color: 'var(--fl-subtle)', fontFamily: MONO, marginTop: 12 }}>
        {t('settings.integrations.empty_hint')}
      </p>
    </div>
  );
}

const SubHead = ({ title, desc }) => (
  <div style={{ marginBottom: 12 }}>
    <h4 style={{ margin: 0, fontSize: 13.5, fontFamily: UI, fontWeight: 600, color: 'var(--fl-text)' }}>{title}</h4>
    {desc && <p style={{ margin: '3px 0 0', fontSize: 11.5, color: 'var(--fl-muted)', fontFamily: UI }}>{desc}</p>}
  </div>
);

const Row = ({ children }) => (
  <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', padding: '10px 0', borderBottom: '1px solid var(--fl-border2)' }}>{children}</div>
);

/* ── TAXII / OpenCTI feeds ──────────────────────────────────────────────── */
const EMPTY_FEED = { name: '', url: '', api_root: '', collection_id: '', auth_type: 'none', auth_value: '' };

function TaxiiFeeds() {
  const { t } = useTranslation();
  const [feeds, setFeeds] = useState(null);
  const [form, setForm]   = useState(null);          // null = closed, object = open
  const [busy, setBusy]   = useState('');            // id being synced/deleted
  const [msg, setMsg]     = useState('');

  const load = () => threatIntelAPI.feeds().then(r => setFeeds(Array.isArray(r.data) ? r.data : [])).catch(() => setFeeds([]));
  useEffect(() => { load(); }, []);

  const openCtiPreset = () => setForm({
    ...EMPTY_FEED, name: 'OpenCTI', auth_type: 'bearer',
    url: 'https://opencti.example.com/taxii2/root',
    collection_id: '',
  });

  const add = async () => {
    if (!form.name || !form.url) return;
    setMsg('');
    try { await threatIntelAPI.addFeed(form); setForm(null); load(); setMsg(t('settings.integrations.taxii.added')); }
    catch (e) { setMsg(`✗ ${e.response?.data?.error || t('common.error')}`); }
  };
  const del = async (id) => {
    if (!confirm(t('settings.integrations.taxii.delete_confirm'))) return;
    setBusy(id);
    try { await threatIntelAPI.deleteFeed(id); load(); } catch { /* ignore */ } finally { setBusy(''); }
  };
  const sync = async (id) => {
    setBusy(id); setMsg('');
    try { const r = await threatIntelAPI.fetchFeed(id); setMsg(`✓ ${r.data?.message || t('settings.integrations.taxii.synced')}`); load(); }
    catch (e) { setMsg(`✗ ${e.response?.data?.error || t('common.error')}`); } finally { setBusy(''); }
  };

  return (
    <div style={{ marginTop: 34, paddingTop: 26, borderTop: '1px solid var(--fl-border)' }}>
      <SubHead title={t('settings.integrations.taxii.title')} desc={t('settings.integrations.taxii.desc')} />

      {feeds === null ? <Skeletons n={2} /> : feeds.length === 0 ? (
        <p style={{ fontSize: 12, color: 'var(--fl-muted)', fontFamily: UI }}>{t('settings.integrations.taxii.none')}</p>
      ) : feeds.map(f => (
        <Row key={f.id}>
          <div style={{ flex: 1, minWidth: 160 }}>
            <div style={{ fontSize: 12.5, color: 'var(--fl-text)', fontFamily: UI, fontWeight: 500 }}>{f.name}</div>
            <div style={{ fontSize: 10.5, color: 'var(--fl-muted)', fontFamily: MONO, wordBreak: 'break-all' }}>{f.url}</div>
          </div>
          <span style={{ fontSize: 10, fontFamily: MONO, color: 'var(--fl-dim)' }}>
            {t('settings.integrations.taxii.indicators', { count: f.indicator_count || 0 })}
          </span>
          <Btn onClick={() => sync(f.id)} disabled={busy === f.id} title={t('settings.integrations.taxii.sync')}>
            {busy === f.id ? <Loader2 size={12} className="spin" /> : <RefreshCw size={12} />} {t('settings.integrations.taxii.sync')}
          </Btn>
          <Btn variant="danger" onClick={() => del(f.id)} disabled={busy === f.id} title={t('common.delete')}><Trash2 size={12} /></Btn>
        </Row>
      ))}

      {form ? (
        <div style={{ marginTop: 14, padding: 14, border: '1px solid var(--fl-border)', borderRadius: 8, background: 'var(--fl-card)' }}>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <Input placeholder={t('settings.integrations.taxii.name_ph')} value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} width={150} />
            <Input placeholder={t('settings.integrations.taxii.url_ph')} value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))} width={300} />
            <Input placeholder={t('settings.integrations.taxii.collection_ph')} value={form.collection_id} onChange={e => setForm(f => ({ ...f, collection_id: e.target.value }))} width={170} />
            <select value={form.auth_type} onChange={e => setForm(f => ({ ...f, auth_type: e.target.value }))}
              style={{ padding: '7px 10px', borderRadius: 6, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 12 }}>
              <option value="none">none</option><option value="bearer">bearer</option><option value="basic">basic</option>
            </select>
            {form.auth_type !== 'none' && (
              <Input type="password" placeholder={t('settings.integrations.taxii.token_ph')} value={form.auth_value} onChange={e => setForm(f => ({ ...f, auth_value: e.target.value }))} width={220} />
            )}
          </div>
          <div style={{ marginTop: 12, display: 'flex', gap: 10 }}>
            <Btn variant="primary" onClick={add} disabled={!form.name || !form.url}>{t('common.add')}</Btn>
            <Btn onClick={() => setForm(null)}>{t('common.cancel')}</Btn>
          </div>
        </div>
      ) : (
        <div style={{ marginTop: 14, display: 'flex', gap: 10, alignItems: 'center' }}>
          <Btn variant="primary" onClick={() => setForm({ ...EMPTY_FEED })}><Plus size={13} /> {t('settings.integrations.taxii.add')}</Btn>
          <Btn onClick={openCtiPreset}>{t('settings.integrations.taxii.opencti_preset')}</Btn>
          <Msg msg={msg} />
        </div>
      )}
    </div>
  );
}

/* ── MISP instances ─────────────────────────────────────────────────────── */
const EMPTY_MISP = { name: '', url: '', api_key: '', verify_ssl: true };

function MispInstances() {
  const { t } = useTranslation();
  const [items, setItems] = useState(null);
  const [form, setForm]   = useState(null);
  const [busy, setBusy]   = useState('');
  const [msg, setMsg]     = useState('');

  const load = () => mispAPI.instances().then(r => setItems(Array.isArray(r.data) ? r.data : [])).catch(() => setItems([]));
  useEffect(() => { load(); }, []);

  const add = async () => {
    if (!form.name || !form.url || !form.api_key) return;
    setMsg('');
    try { await mispAPI.addInstance(form); setForm(null); load(); }
    catch (e) { setMsg(`✗ ${e.response?.data?.error || t('common.error')}`); }
  };
  const del = async (id) => {
    if (!confirm(t('settings.integrations.misp.delete_confirm'))) return;
    setBusy(id); try { await mispAPI.deleteInstance(id); load(); } catch { /* ignore */ } finally { setBusy(''); }
  };
  const test = async (id) => {
    setBusy(id); setMsg('');
    try { const r = await mispAPI.testInstance(id); setMsg(r.data?.ok ? `✓ ${t('settings.integrations.misp.test_ok')} ${r.data.version ? `(v${r.data.version})` : ''}` : `✗ ${t('settings.integrations.misp.test_fail')}`); }
    catch (e) { setMsg(`✗ ${e.response?.data?.error || t('common.error')}`); } finally { setBusy(''); }
  };
  const sync = async (id) => {
    setBusy(id); setMsg('');
    try { const r = await mispAPI.syncInstance(id); setMsg(`✓ ${r.data?.message || t('settings.integrations.misp.synced')}`); load(); }
    catch (e) { setMsg(`✗ ${e.response?.data?.error || t('common.error')}`); } finally { setBusy(''); }
  };

  return (
    <div style={{ marginTop: 34, paddingTop: 26, borderTop: '1px solid var(--fl-border)' }}>
      <SubHead title={t('settings.integrations.misp.title')} desc={t('settings.integrations.misp.desc')} />

      {items === null ? <Skeletons n={2} /> : items.length === 0 ? (
        <p style={{ fontSize: 12, color: 'var(--fl-muted)', fontFamily: UI }}>{t('settings.integrations.misp.none')}</p>
      ) : items.map(m => (
        <Row key={m.id}>
          <div style={{ flex: 1, minWidth: 160 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
              <span style={{ fontSize: 12.5, color: 'var(--fl-text)', fontFamily: UI, fontWeight: 500 }}>{m.name}</span>
              {m.verify_ssl === false && <span style={{ fontSize: 9, fontFamily: MONO, color: 'var(--fl-warn)', border: '1px solid color-mix(in srgb, var(--fl-warn) 30%, transparent)', borderRadius: 3, padding: '0 5px' }}>TLS off</span>}
            </div>
            <div style={{ fontSize: 10.5, color: 'var(--fl-muted)', fontFamily: MONO, wordBreak: 'break-all' }}>{m.url}</div>
          </div>
          <span style={{ fontSize: 10, fontFamily: MONO, color: 'var(--fl-dim)' }}>
            {t('settings.integrations.taxii.indicators', { count: m.indicator_count || 0 })}
          </span>
          <Btn onClick={() => test(m.id)} disabled={busy === m.id} title={t('settings.integrations.misp.test')}>
            {busy === m.id ? <Loader2 size={12} className="spin" /> : <Check size={12} />} {t('settings.integrations.misp.test')}
          </Btn>
          <Btn onClick={() => sync(m.id)} disabled={busy === m.id} title={t('settings.integrations.misp.sync')}>
            {busy === m.id ? <Loader2 size={12} className="spin" /> : <RefreshCw size={12} />} {t('settings.integrations.misp.sync')}
          </Btn>
          <Btn variant="danger" onClick={() => del(m.id)} disabled={busy === m.id} title={t('common.delete')}><Trash2 size={12} /></Btn>
        </Row>
      ))}

      {form ? (
        <div style={{ marginTop: 14, padding: 14, border: '1px solid var(--fl-border)', borderRadius: 8, background: 'var(--fl-card)' }}>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <Input placeholder={t('settings.integrations.misp.name_ph')} value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} width={150} />
            <Input placeholder={t('settings.integrations.misp.url_ph')} value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))} width={280} />
            <Input type="password" placeholder={t('settings.integrations.misp.key_ph')} value={form.api_key} onChange={e => setForm(f => ({ ...f, api_key: e.target.value }))} width={240} />
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 7, marginTop: 12, fontSize: 11.5, color: 'var(--fl-dim)', fontFamily: UI, cursor: 'pointer' }}>
            <input type="checkbox" checked={form.verify_ssl} onChange={e => setForm(f => ({ ...f, verify_ssl: e.target.checked }))} />
            {t('settings.integrations.misp.verify_ssl')}
            <span style={{ fontSize: 10, color: 'var(--fl-warn)', fontFamily: MONO }}>{t('settings.integrations.misp.verify_ssl_hint')}</span>
          </label>
          <div style={{ marginTop: 12, display: 'flex', gap: 10 }}>
            <Btn variant="primary" onClick={add} disabled={!form.name || !form.url || !form.api_key}>{t('common.add')}</Btn>
            <Btn onClick={() => setForm(null)}>{t('common.cancel')}</Btn>
          </div>
        </div>
      ) : (
        <div style={{ marginTop: 14, display: 'flex', gap: 10, alignItems: 'center' }}>
          <Btn variant="primary" onClick={() => setForm({ ...EMPTY_MISP })}><Plus size={13} /> {t('settings.integrations.misp.add')}</Btn>
          <Msg msg={msg} />
        </div>
      )}
    </div>
  );
}

export default function IntegrationsSection() {
  const { t } = useTranslation();
  return (
    <>
      <SectionHead title={t('settings.integrations.title')} desc={t('settings.integrations.desc')} />
      <ApiKeys />
      <TaxiiFeeds />
      <MispInstances />
    </>
  );
}
