import { useState } from 'react';
import { Eye, EyeOff, AlertCircle } from 'lucide-react';
import HeimdallLogo from '../components/ui/HeimdallLogo';
import { useTranslation } from 'react-i18next';
import { authAPI } from '../utils/api';
import Button from '../components/ui/Button';

export default function LoginPage({ onLogin }) {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const { data } = await authAPI.login({ username, password });
      onLogin(data.user, data.token, data.refreshToken);
    } catch (err) {
      setError(err.response?.data?.error || t('login.error'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: 'var(--fl-bg)' }}>
      <div
        className="w-full max-w-sm p-8 rounded-xl border"
        style={{ background: 'var(--fl-panel)', borderColor: 'var(--fl-border)', boxShadow: '0 8px 32px rgba(0,0,0,0.4)' }}
      >
        
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center gap-3 mb-3">
            <div
              className="p-2.5 rounded-xl"
              style={{
                background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)',
                border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)',
              }}
            >
              <HeimdallLogo size={26} style={{ color: 'var(--fl-accent)' }} id="login" />
            </div>
            <span className="font-mono font-bold text-xl tracking-widest" style={{ color: 'var(--fl-text)' }}>
              HEIMDALL<span style={{ color: 'var(--fl-accent)' }}> DFIR</span>
            </span>
          </div>
          <p className="text-xs font-mono uppercase tracking-widest" style={{ color: 'var(--fl-dim)' }}>
            See the unseen. Hunt the unknown.
          </p>
        </div>

        {error && (
          <div
            className="flex items-center gap-2 p-3 mb-4 rounded-lg text-sm"
            style={{
              background: 'color-mix(in srgb, var(--fl-danger) 10%, transparent)',
              border: '1px solid color-mix(in srgb, var(--fl-danger) 20%, transparent)',
              color: 'var(--fl-danger)',
            }}
          >
            <AlertCircle size={16} /> {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="fl-label block mb-2">{t('login.username')}</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="fl-input"
              placeholder={t('login.username')}
              required
            />
          </div>

          <div>
            <label className="fl-label block mb-2">{t('login.password')}</label>
            <div className="relative">
              <input
                type={showPw ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="fl-input"
                style={{ paddingRight: 40 }}
                placeholder="••••••••"
                required
              />
              <button
                type="button"
                onClick={() => setShowPw(!showPw)}
                className="absolute right-3 top-1/2 -translate-y-1/2"
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)' }}
              >
                {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <Button
            type="submit"
            variant="primary"
            loading={loading}
            style={{ width: '100%', justifyContent: 'center', padding: '10px 14px' }}
          >
            {t('login.submit')}
          </Button>
        </form>
      </div>
    </div>
  );
}
