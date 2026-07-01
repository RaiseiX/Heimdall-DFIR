import { useState, useEffect, useCallback } from 'react';
import { Plus, KeyRound, Trash2, X } from 'lucide-react';
import { usersAPI, authAPI } from '../../utils/api';
import { currentUser } from '../../utils/auth';
import { MONO, SectionHead, Btn, Input, Table, tdStyle, Skeletons, Empty, Msg } from './shared';
import { useTranslation } from 'react-i18next';

export default function TeamSection() {
  const { t } = useTranslation();
  const me = currentUser();
  const [users, setUsers]     = useState([]);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg]         = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [newUser, setNewUser] = useState({ username: '', full_name: '', password: '', role: 'analyst' });
  const [pwdFor, setPwdFor]   = useState(null);   // user id being password-reset
  const [pwdVal, setPwdVal]   = useState('');
  const [confirmDel, setConfirmDel] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    usersAPI.list().then(r => setUsers(r.data || [])).catch(() => setUsers([])).finally(() => setLoading(false));
  }, []);
  useEffect(() => { load(); }, [load]);

  const flash = (m) => { setMsg(m); setTimeout(() => setMsg(''), 3000); };

  const changeRole = async (id, role) => {
    try { await usersAPI.update(id, { role }); load(); flash(t('settings.team.role_updated')); }
    catch { flash(t('settings.messages.failed')); }
  };
  const toggleActive = async (u) => {
    try { await usersAPI.update(u.id, { is_active: !u.is_active }); load(); flash(u.is_active ? t('settings.team.account_disabled') : t('settings.team.account_enabled')); }
    catch { flash(t('settings.messages.failed')); }
  };
  const resetPwd = async () => {
    if (!pwdFor || pwdVal.length < 8) return;
    try { await usersAPI.changePassword(pwdFor, pwdVal); setPwdFor(null); setPwdVal(''); flash(t('settings.team.password_changed')); }
    catch { flash(t('settings.messages.failed')); }
  };
  const del = async (id) => {
    try { await usersAPI.delete(id); setConfirmDel(null); load(); flash(t('settings.team.account_deleted')); }
    catch { flash(t('settings.messages.failed')); }
  };
  const create = async () => {
    if (!newUser.username || !newUser.full_name || newUser.password.length < 8) { flash(t('settings.team.required_fields')); return; }
    try {
      await authAPI.register(newUser);
      setNewUser({ username: '', full_name: '', password: '', role: 'analyst' });
      setShowCreate(false); load(); flash(t('settings.team.account_created'));
    } catch (e) { flash(`✗ ${e.response?.data?.error || t('common.error')}`); }
  };

  const selStyle = { padding: '5px 8px', borderRadius: 6, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 11, cursor: 'pointer' };

  return (
    <>
      <SectionHead title={t('settings.team.title')} desc={t('settings.team.desc')} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 14 }}>
        <Btn variant="primary" onClick={() => setShowCreate(s => !s)}><Plus size={13} /> {t('settings.team.create_account')}</Btn>
        <Msg msg={msg} />
      </div>

      {showCreate && (
        <div style={{ marginTop: 12, padding: 14, border: '1px solid var(--fl-border)', borderRadius: 8, background: 'var(--fl-panel)', display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
          <Input placeholder={t('settings.team.username')} value={newUser.username} onChange={e => setNewUser(s => ({ ...s, username: e.target.value }))} width={140} />
          <Input placeholder={t('settings.team.full_name')} value={newUser.full_name} onChange={e => setNewUser(s => ({ ...s, full_name: e.target.value }))} width={170} />
          <Input placeholder={t('settings.team.password_min')} type="password" value={newUser.password} onChange={e => setNewUser(s => ({ ...s, password: e.target.value }))} width={160} />
          <select value={newUser.role} onChange={e => setNewUser(s => ({ ...s, role: e.target.value }))} style={selStyle}>
            <option value="analyst">analyst</option>
            <option value="team_lead">team lead</option>
            <option value="admin">admin</option>
          </select>
          <Btn variant="ok" onClick={create}>{t('common.confirm')}</Btn>
          <Btn onClick={() => setShowCreate(false)}><X size={12} /></Btn>
        </div>
      )}

      {loading ? <Skeletons n={3} /> : users.length === 0 ? <Empty text={t('settings.team.no_accounts')} /> : (
        <Table cols={[[t('settings.team.user'), null], [t('settings.team.username'), 130], [t('settings.team.role'), 110], [t('settings.team.status'), 90], [t('settings.team.last_login'), 170], ['', 120]]}>
          {users.map(u => (
            <tr key={u.id}>
              <td style={tdStyle}>{u.full_name}</td>
              <td style={{ ...tdStyle, fontFamily: MONO, fontSize: 11, color: 'var(--fl-dim)' }}>@{u.username}</td>
              <td style={tdStyle}>
                <select value={u.role} disabled={u.id === me.id} onChange={e => changeRole(u.id, e.target.value)} style={{ ...selStyle, opacity: u.id === me.id ? 0.5 : 1 }}>
                  <option value="analyst">analyst</option>
                  <option value="team_lead">team lead</option>
                  <option value="admin">admin</option>
                </select>
              </td>
              <td style={tdStyle}>
                <button onClick={() => u.id !== me.id && toggleActive(u)} title={u.id === me.id ? t('settings.team.your_account') : t('settings.team.toggle')}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'none', border: 'none', cursor: u.id === me.id ? 'default' : 'pointer', fontFamily: MONO, fontSize: 11, color: u.is_active ? 'var(--fl-ok)' : 'var(--fl-danger)' }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: u.is_active ? 'var(--fl-ok)' : 'var(--fl-danger)' }} />
                  {u.is_active ? t('settings.team.active') : t('settings.team.inactive')}
                </button>
              </td>
              <td style={{ ...tdStyle, fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-muted)' }}>
                {u.last_login ? new Date(u.last_login).toLocaleString() : t('common.never')}
              </td>
              <td style={{ ...tdStyle, whiteSpace: 'nowrap' }}>
                <button onClick={() => { setPwdFor(pwdFor === u.id ? null : u.id); setPwdVal(''); }} title={t('settings.team.reset_password')}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', padding: '0 4px' }}><KeyRound size={13} /></button>
                {u.id !== me.id && (
                  confirmDel === u.id
                    ? <Btn variant="danger" onClick={() => del(u.id)}>{t('common.confirm')}</Btn>
                    : <button onClick={() => setConfirmDel(u.id)} title={t('common.delete')}
                        style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', padding: '0 4px' }}><Trash2 size={13} /></button>
                )}
              </td>
            </tr>
          ))}
        </Table>
      )}

      {pwdFor && (
        <div style={{ marginTop: 10, display: 'flex', gap: 8, alignItems: 'center' }}>
          <Input placeholder={t('settings.team.new_password_min')} type="password" value={pwdVal} onChange={e => setPwdVal(e.target.value)} width={220} />
          <Btn variant="ok" onClick={resetPwd} disabled={pwdVal.length < 8}>{t('settings.team.apply')}</Btn>
          <Btn onClick={() => setPwdFor(null)}>{t('common.cancel')}</Btn>
        </div>
      )}
    </>
  );
}
