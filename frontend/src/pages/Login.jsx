import { useState } from 'react';

export default function Login({ onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    setError('');
    setLoading(true);

    try {
      const res = await fetch("http://localhost:3001/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();

      if (!res.ok || !data.token) {
        throw new Error(data.error || 'Login failed (no token returned)');
      }

      localStorage.setItem("token", data.token);
      onLogin(data.token);

    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  

  return (
    <div style={{
      width: '100vw', height: '100vh',
      background: 'linear-gradient(135deg, #fff5f5 0%, #fff 60%, #ffeaea 100%)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontFamily: 'Inter, sans-serif',
    }}>
      <div style={{ display: 'flex', width: 900, height: 520, borderRadius: 24, overflow: 'hidden', boxShadow: '0 20px 60px rgba(0,0,0,0.1)' }}>

        {/* Left panel */}
        <div style={{ flex: 1, background: '#e8483a', padding: 48, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ width: 36, height: 36, background: 'rgba(255,255,255,0.2)', borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 40 }}>
              <div style={{ width: 14, height: 14, background: '#fff', borderRadius: 3 }}></div>
            </div>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#fff', lineHeight: 1.3, marginBottom: 16 }}>
              Security Operations<br />Center Platform
            </div>
            <div style={{ fontSize: 14, color: 'rgba(255,255,255,0.7)', lineHeight: 1.7 }}>
              Monitor threats, track incidents, and protect your clients in real time.
            </div>
          </div>
          <div style={{ display: 'flex', gap: 12 }}>
            {['Alerts', 'Live Logs', 'Reports'].map(t => (
              <div key={t} style={{ background: 'rgba(255,255,255,0.15)', borderRadius: 8, padding: '8px 14px', fontSize: 12, color: '#fff' }}>{t}</div>
            ))}
          </div>
        </div>

        {/* Right panel */}
        <div style={{ flex: 1, background: '#fff', padding: 48, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#1a1a2e', marginBottom: 6 }}>Welcome back</div>
          <div style={{ fontSize: 13, color: '#9a9a9a', marginBottom: 36 }}>Sign in to your SOC dashboard</div>

          {error && (
            <div style={{ background: '#fff5f5', border: '1px solid #ffd0d0', borderRadius: 10, padding: '10px 14px', fontSize: 13, color: '#e8483a', marginBottom: 20 }}>
              {error}
            </div>
          )}

          <div style={{ marginBottom: 18 }}>
            <div style={{ fontSize: 12, color: '#9a9a9a', marginBottom: 8, fontWeight: 500 }}>Email address</div>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSubmit()}
              placeholder="admin@soc.com"
              style={{ width: '100%', padding: '12px 16px', border: '1.5px solid #f0f0f0', borderRadius: 10, fontSize: 14, outline: 'none', background: '#fafafa', color: '#1a1a2e', fontFamily: 'Inter, sans-serif' }}
            />
          </div>

          <div style={{ marginBottom: 28 }}>
            <div style={{ fontSize: 12, color: '#9a9a9a', marginBottom: 8, fontWeight: 500 }}>Password</div>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSubmit()}
              placeholder="••••••••"
              style={{ width: '100%', padding: '12px 16px', border: '1.5px solid #f0f0f0', borderRadius: 10, fontSize: 14, outline: 'none', background: '#fafafa', color: '#1a1a2e', fontFamily: 'Inter, sans-serif' }}
            />
          </div>

          <button
            onClick={handleSubmit}
            disabled={loading}
            style={{ width: '100%', padding: '13px', background: loading ? '#f0f0f0' : '#e8483a', color: loading ? '#aaa' : '#fff', border: 'none', borderRadius: 10, fontSize: 14, fontWeight: 600, cursor: loading ? 'not-allowed' : 'pointer', fontFamily: 'Inter, sans-serif', transition: 'background 0.2s' }}
          >
            {loading ? 'Signing in...' : 'Sign in →'}
          </button>
        </div>
      </div>
    </div>
  );
}