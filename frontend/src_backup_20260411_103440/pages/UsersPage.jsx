import { useState } from 'react';
import { Users, Plus, Shield, UserCheck, UserX, X } from 'lucide-react';

const DEMO_USERS = [
  { id: '1', username: 'admin', email: 'admin@heimdall.local', full_name: 'Administrateur', role: 'admin', is_active: true, last_login: '2026-02-16T08:00:00Z', created_at: '2026-01-01T00:00:00Z' },
  { id: '2', username: 'analyst', email: 'analyst@heimdall.local', full_name: 'Analyste Forensique', role: 'analyst', is_active: true, last_login: '2026-02-15T14:30:00Z', created_at: '2026-01-01T00:00:00Z' },
  { id: '3', username: 'dupont', email: 'dupont@heimdall.local', full_name: 'Agent Dupont', role: 'admin', is_active: true, last_login: '2026-02-16T07:45:00Z', created_at: '2026-01-15T00:00:00Z' },
  { id: '4', username: 'martin', email: 'martin@heimdall.local', full_name: 'Agent Martin', role: 'analyst', is_active: true, last_login: '2026-02-14T16:00:00Z', created_at: '2026-01-20T00:00:00Z' },
  { id: '5', username: 'lefevre', email: 'lefevre@heimdall.local', full_name: 'Agent Lefèvre', role: 'analyst', is_active: false, last_login: null, created_at: '2026-02-01T00:00:00Z' },
];

export default function UsersPage() {
  const [users] = useState(DEMO_USERS);
  const [showNew, setShowNew] = useState(false);
  const [newUser, setNewUser] = useState({ username: '', email: '', full_name: '', password: '', role: 'analyst' });

  const adminCount = users.filter(u => u.role === 'admin').length;
  const analystCount = users.filter(u => u.role === 'analyst').length;
  const inactiveCount = users.filter(u => !u.is_active).length;

  return (
    <div className="p-6">
      
      <div className="fl-header">
        <div>
          <h1 className="fl-header-title">Gestion des Utilisateurs</h1>
          <p className="fl-header-sub">{users.length} utilisateurs · {users.filter(u => u.is_active).length} actifs</p>
        </div>
        <button onClick={() => setShowNew(true)} className="fl-btn fl-btn-primary">
          <Plus size={15} /> Nouvel utilisateur
        </button>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-6">
        {[
          { label: 'Administrateurs', value: adminCount, color: '#d97c20', icon: Shield },
          { label: 'Analystes', value: analystCount, color: '#4d82c0', icon: UserCheck },
          { label: 'Inactifs', value: inactiveCount, color: '#da3633', icon: UserX },
        ].map(s => (
          <div key={s.label} className="rounded-lg p-4 border flex items-center gap-4"
            style={{ background: '#1c2333', borderColor: '#30363d', borderLeft: `3px solid ${s.color}` }}>
            <div className="w-9 h-9 rounded-lg flex items-center justify-center"
              style={{ background: `${s.color}14` }}>
              <s.icon size={18} style={{ color: s.color }} />
            </div>
            <div>
              <div className="font-mono font-bold text-2xl" style={{ color: '#e6edf3' }}>{s.value}</div>
              <div className="text-xs" style={{ color: '#7d8590' }}>{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="fl-card" style={{ overflow: 'hidden' }}>
        <table className="fl-table">
          <thead>
            <tr>
              <th>Utilisateur</th>
              <th>Email</th>
              <th>Rôle</th>
              <th>Statut</th>
              <th>Dernière connexion</th>
              <th>Créé le</th>
            </tr>
          </thead>
          <tbody>
            {users.map(u => (
              <tr key={u.id}>
                <td>
                  <div className="font-semibold text-sm" style={{ color: '#e6edf3' }}>{u.full_name}</div>
                  <div className="text-xs font-mono" style={{ color: '#7d8590' }}>@{u.username}</div>
                </td>
                <td className="fl-td-mono fl-td-dim">{u.email}</td>
                <td>
                  <span className="fl-badge" style={{
                    background: u.role === 'admin' ? '#d97c2014' : '#4d82c014',
                    color: u.role === 'admin' ? '#d97c20' : '#4d82c0',
                    border: `1px solid ${u.role === 'admin' ? '#d97c2030' : '#4d82c030'}`,
                  }}>
                    {u.role === 'admin' && <Shield size={10} className="inline mr-1" />}
                    {u.role}
                  </span>
                </td>
                <td>
                  <span className="fl-badge" style={{
                    background: u.is_active ? '#3fb95014' : '#da363314',
                    color: u.is_active ? '#3fb950' : '#da3633',
                    border: `1px solid ${u.is_active ? '#3fb95030' : '#da363330'}`,
                  }}>
                    {u.is_active ? 'Actif' : 'Inactif'}
                  </span>
                </td>
                <td className="fl-td-dim" style={{ fontSize: '0.8125rem' }}>
                  {u.last_login ? new Date(u.last_login).toLocaleString('fr-FR') : '—'}
                </td>
                <td className="fl-td-dim" style={{ fontSize: '0.8125rem' }}>
                  {new Date(u.created_at).toLocaleDateString('fr-FR')}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showNew && (
        <div className="fl-modal-overlay" onClick={e => e.target === e.currentTarget && setShowNew(false)}>
          <div className="fl-modal">
            <div className="fl-modal-header">
              <Plus size={16} style={{ color: '#4d82c0' }} /> Nouvel utilisateur
            </div>
            <div className="fl-modal-body">
              <div className="space-y-4">
                {[
                  { key: 'full_name', label: 'Nom complet', ph: 'Jean Dupont' },
                  { key: 'username', label: 'Identifiant', ph: 'jdupont' },
                  { key: 'email', label: 'Email', ph: 'jean@heimdall.local' },
                  { key: 'password', label: 'Mot de passe', ph: '••••••••', type: 'password' },
                ].map(f => (
                  <div key={f.key}>
                    <label className="fl-label">{f.label}</label>
                    <input
                      value={newUser[f.key]}
                      onChange={e => setNewUser({ ...newUser, [f.key]: e.target.value })}
                      type={f.type || 'text'}
                      placeholder={f.ph}
                      className="fl-input w-full"
                    />
                  </div>
                ))}
                <div>
                  <label className="fl-label">Rôle</label>
                  <div className="flex gap-3">
                    {[
                      { key: 'analyst', label: 'Analyste', color: '#4d82c0' },
                      { key: 'admin', label: 'Administrateur', color: '#d97c20' },
                    ].map(r => (
                      <button
                        key={r.key}
                        onClick={() => setNewUser({ ...newUser, role: r.key })}
                        className="fl-btn fl-btn-sm flex-1"
                        style={{
                          background: newUser.role === r.key ? `${r.color}18` : 'transparent',
                          color: r.color,
                          border: `1px solid ${newUser.role === r.key ? r.color + '50' : '#30363d'}`,
                          fontWeight: newUser.role === r.key ? 700 : 400,
                        }}
                      >
                        {r.key === 'admin' && <Shield size={12} />} {r.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
            <div className="fl-modal-footer">
              <button onClick={() => setShowNew(false)} className="fl-btn fl-btn-secondary">Annuler</button>
              <button
                onClick={() => setShowNew(false)}
                className="fl-btn fl-btn-primary"
                disabled={!newUser.full_name.trim() || !newUser.username.trim()}
              >
                Créer l'utilisateur
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
