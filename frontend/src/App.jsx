import { useState } from 'react';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('soc_token'));

  if (!token) return <Login onLogin={t => { localStorage.setItem('soc_token', t); setToken(t); }} />;
  return <Dashboard token={token} onLogout={() => { localStorage.removeItem('soc_token'); setToken(null); }} />;
}