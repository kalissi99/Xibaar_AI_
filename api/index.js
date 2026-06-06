const https = require('https');
const { execSync } = require('child_process');
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { Client } = require('@elastic/elasticsearch');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const es = new Client({ node: process.env.ELASTICSEARCH_URL });
const JWT_SECRET = process.env.JWT_SECRET || 'changeme';

// ── MITRE ATT&CK mapping ─────────────────────────────────────────────────────
const MITRE = {
  'failed_login':          { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', severity: 'medium' },
  'account_lockout':       { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', severity: 'medium' },
  'brute_force':           { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', severity: 'high' },
  'credential_dump':       { id: 'T1003', name: 'Credential Dumping', tactic: 'Credential Access', severity: 'critical' },
  'new_admin_account':     { id: 'T1136', name: 'Create Account', tactic: 'Persistence', severity: 'high' },
  'scheduled_task':        { id: 'T1053', name: 'Scheduled Task', tactic: 'Persistence', severity: 'medium' },
  'usb_or_file_access':    { id: 'T1052', name: 'Exfiltration over USB', tactic: 'Exfiltration', severity: 'high' },
  'powershell_exec':       { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', severity: 'medium' },
  'cmd_execution':         { id: 'T1059.003', name: 'Windows Command Shell', tactic: 'Execution', severity: 'medium' },
  'firewall_disabled':     { id: 'T1562.004', name: 'Disable Firewall', tactic: 'Defense Evasion', severity: 'high' },
  'antivirus_disabled':    { id: 'T1562.001', name: 'Disable Antivirus', tactic: 'Defense Evasion', severity: 'critical' },
  'service_status_change': { id: 'T1489', name: 'Service Stop', tactic: 'Impact', severity: 'high' },
  'ransomware':            { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', severity: 'critical' },
  'remote_desktop':        { id: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'Lateral Movement', severity: 'high' },
  'network_scan':          { id: 'T1046', name: 'Network Service Scanning', tactic: 'Discovery', severity: 'medium' },
};

// ── Auth middleware ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── DB setup ──────────────────────────────────────────────────────────────────
async function initDB() {
  let retries = 10;
  while (retries > 0) {
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          company_id TEXT NOT NULL,
          role TEXT DEFAULT 'analyst'
        );
        CREATE TABLE IF NOT EXISTS alerts (
          id SERIAL PRIMARY KEY,
          company_id TEXT NOT NULL,
          alert_type TEXT NOT NULL,
          severity TEXT NOT NULL,
          machine TEXT,
          message TEXT,
          es_index TEXT,
          mitre_id TEXT,
          mitre_name TEXT,
          mitre_tactic TEXT,
          created_at TIMESTAMP DEFAULT NOW(),
          acknowledged BOOLEAN DEFAULT FALSE
        );
        CREATE TABLE IF NOT EXISTS machines (
          id SERIAL PRIMARY KEY,
          company_id TEXT NOT NULL,
          name TEXT NOT NULL,
          ip TEXT,
          last_seen TIMESTAMP DEFAULT NOW(),
          UNIQUE(company_id, name)
        );
      `);

      await pool.query(`
        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_id TEXT;
        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_name TEXT;
        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactic TEXT;
      `).catch(() => {});

      console.log('Database ready');
      return;
    } catch (e) {
      console.log(`DB not ready, retrying... (${retries} left): ${e.message}`);
      retries--;
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  console.error('Could not connect to database');
}

initDB();

// ── Routes ────────────────────────────────────────────────────────────────────

// Register
app.post('/api/register', async (req, res) => {
  const { email, password, company_id } = req.body;
  if (!email || !password || !company_id)
    return res.status(400).json({ error: 'email, password, company_id required' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password, company_id) VALUES ($1, $2, $3) RETURNING id, email, company_id',
      [email, hashed, company_id]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: 'Bad credentials' });
    const token = jwt.sign(
      { id: user.id, company_id: user.company_id, role: user.role },
      JWT_SECRET,
      { expiresIn: '12h' }
    );
    res.json({ token, company_id: user.company_id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Get alerts
app.get('/api/alerts', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM alerts WHERE company_id=$1 ORDER BY created_at DESC LIMIT 200',
      [req.user.company_id]
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Acknowledge alert
app.patch('/api/alerts/:id/ack', auth, async (req, res) => {
  try {
    await pool.query(
      'UPDATE alerts SET acknowledged=TRUE WHERE id=$1 AND company_id=$2',
      [req.params.id, req.user.company_id]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Live logs from Elasticsearch
app.get('/api/logs', auth, async (req, res) => {
  const { size = 100 } = req.query;
  try {
    const result = await es.search({
      index: `soc-logs-${req.user.company_id}-*`,
      size: parseInt(size),
      sort: [{ '@timestamp': { order: 'desc' } }],
      query: { match_all: {} }
    });
    res.json(result.hits.hits.map(h => h._source));
  } catch (e) {
    res.json([]);
  }
});

// Stats (last 24h)
app.get('/api/stats', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT severity, COUNT(*) as count
      FROM alerts
      WHERE company_id=$1 AND created_at > NOW() - INTERVAL '24 hours'
      GROUP BY severity
    `, [req.user.company_id]);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Machines
app.get('/api/machines', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM machines WHERE company_id=$1 ORDER BY last_seen DESC',
      [req.user.company_id]
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// MITRE ATT&CK summary
app.get('/api/mitre', auth, async (req, res) => {
  try {
    const { rows: mitreRows } = await pool.query(`
      SELECT 
        COALESCE(mitre_id, mitre_name) as mitre_id,
        mitre_name,
        mitre_tactic,
        COUNT(*) as count
      FROM alerts
      WHERE company_id=$1
      GROUP BY mitre_id, mitre_name, mitre_tactic
      ORDER BY count DESC
      LIMIT 10
    `, [req.user.company_id]);
    res.json(mitreRows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Debug MITRE route
app.get('/api/debug/mitre', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, alert_type, severity, mitre_id, mitre_name, mitre_tactic 
      FROM alerts 
      WHERE company_id=$1 
      LIMIT 20
    `, [req.user.company_id]);
    
    const mitreCount = rows.filter(r => r.mitre_id).length;
    
    res.json({
      total_alerts: rows.length,
      alerts_with_mitre: mitreCount,
      alerts: rows
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Ingest endpoint
app.post('/api/logs/ingest', async (req, res) => {
  const log = req.body;
  const machine = log.host?.name || log.machine || log.agent?.name;
  if (machine && log.company_id) {
    try {
      await pool.query(`
        INSERT INTO machines (company_id, name, ip, last_seen)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (company_id, name) DO UPDATE SET last_seen = NOW()
      `, [log.company_id, machine, log.ip || null]);
    } catch (err) {
      console.error('Machine ingest error:', err.message);
    }
  }
  res.json({ ok: true });
});

// Network scan
app.post('/api/network/scan', auth, async (req, res) => {
  const cidr = req.body.cidr || '192.168.1.0/24';
  if (!/^[\d./]+$/.test(cidr))
    return res.status(400).json({ error: 'Invalid CIDR' });
  try {
    const output = execSync(`nmap -sn ${cidr} 2>&1`, { timeout: 60000 }).toString();
    res.json({ scan_time: new Date(), raw: output });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── AI Helper ─────────────────────────────────────────────────────────────
async function callAI(prompt) {
  const GROQ_API_KEY = process.env.GROQ_API_KEY;
  
  if (!GROQ_API_KEY) {
    console.error('GROQ_API_KEY not set');
    return "Configuration API manquante. Veuillez configurer GROQ_API_KEY.";
  }

  try {
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${GROQ_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "llama-3.1-8b-instant",
        messages: [
          {
            role: "system",
            content: "Tu es un assistant SOC spécialisé en cybersécurité. Réponds de manière naturelle, comme un humain. Ne mets pas de JSON dans ta réponse, juste du texte normal."
          },
          { role: "user", content: prompt }
        ],
        temperature: 0.7,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('Groq API error:', data);
      return `Erreur API: ${data.error?.message || 'Erreur inconnue'}`;
    }

    // Retourner juste le texte, pas du JSON
    return data.choices?.[0]?.message?.content || "Je n'ai pas pu générer une réponse.";
    
  } catch (e) {
    console.error('callAI error:', e);
    return `Erreur: ${e.message}`;
  }
}

function buildPrompt({ message, history, alerts, mitre, mode, user }) {
  const alertContext = alerts.length
    ? alerts.map(a =>
        `- ${a.alert_type} (${a.severity}) on ${a.machine} at ${new Date(a.created_at).toLocaleString()}`
      ).join('\n')
    : "No recent alerts.";

  const mitreContext = mitre.length
    ? mitre.map(m =>
        `- ${m.mitre_id} ${m.mitre_name} (${m.mitre_tactic}) x${m.count}`
      ).join('\n')
    : "No MITRE data.";

  const historyText = (history || [])
    .slice(-10)
    .map(h => `${h.role}: ${h.content}`)
    .join('\n');

  return `
MODE: ${mode}

COMPANY: ${user.company_id}

SECURITY ALERTS:
${alertContext}

MITRE DATA:
${mitreContext}

CONVERSATION:
${historyText}

USER MESSAGE:
${message}

RULES:
- If GREETING: respond politely and show system status
- If CHAT: answer like SOC assistant
- Always be concise, actionable, SOC-focused
`;
}

// ── AI Routes ─────────────────────────────────────────────────────────────

// AI Chat
app.post('/api/ai/chat', auth, async (req, res) => {
  const { message, history } = req.body;

  try {
    const { rows: alerts } = await pool.query(
      `SELECT * FROM alerts WHERE company_id=$1 ORDER BY created_at DESC LIMIT 15`,
      [req.user.company_id]
    );

    const { rows: mitre } = await pool.query(
      `SELECT mitre_id, mitre_name, mitre_tactic, COUNT(*) as count
       FROM alerts WHERE company_id=$1 AND mitre_id IS NOT NULL
       GROUP BY mitre_id, mitre_name, mitre_tactic`,
      [req.user.company_id]
    );

    // Construire le prompt simple
    const alertSummary = alerts.length > 0 
      ? `Alertes récentes: ${alerts.map(a => `${a.alert_type} (${a.severity}) sur ${a.machine}`).join(', ')}`
      : "Aucune alerte récente.";

    const prompt = `Contexte: ${alertSummary}
    
Historique: ${(history || []).slice(-5).map(h => `${h.role}: ${h.content}`).join('\n')}

Utilisateur: ${message}

Réponds de façon naturelle et utile en tant qu'assistant SOC. Sois concis.`;

    const response = await callAI(prompt);
    
    // Retourner directement la réponse sans wrapper JSON
    res.json({ response });

  } catch (e) {
    console.error('Chat error:', e);
    res.status(500).json({ response: `Erreur: ${e.message}` });
  }
});
// AI Analyze
app.post('/api/ai/analyze', auth, async (req, res) => {
  try {
    const { rows: alerts } = await pool.query(
      `SELECT * FROM alerts WHERE company_id=$1 ORDER BY created_at DESC LIMIT 20`,
      [req.user.company_id]
    );

    if (!alerts.length) {
      return res.json({
        risk_level: "low",
        summary: "Aucun incident détecté",
        threats: [],
        immediate_actions: ["Continuer la surveillance"],
        recommendations: ["Le système est sain"],
        explanation: "Aucune alerte trouvée"
      });
    }

    const summary = alerts.map(a =>
      `${a.severity} - ${a.alert_type} sur ${a.machine || 'inconnu'}`
    ).join('\n');

    const prompt = `Analyse ces incidents de sécurité:
    
${summary}

Réponds STRICTEMENT en JSON:
{
  "risk_level": "critical|high|medium|low",
  "summary": "résumé court en français",
  "threats": ["menace1", "menace2"],
  "immediate_actions": ["action1", "action2"],
  "recommendations": ["recommandation1", "recommandation2"],
  "explanation": "explication en français simple"
}`;

    const ai = await callAI(prompt);
    const match = ai.match(/\{[\s\S]*\}/);
    
    if (!match) {
      return res.json({
        risk_level: alerts.some(a => a.severity === 'critical') ? 'critical' : 'medium',
        summary: `${alerts.length} alerte(s) détectée(s)`,
        threats: alerts.slice(0, 3).map(a => a.alert_type),
        immediate_actions: ["Vérifier les alertes critiques", "Isoler les machines affectées"],
        recommendations: ["Mettre à jour les signatures", "Revoir les logs"],
        explanation: `Analyse de ${alerts.length} alertes récentes`
      });
    }

    return res.json(JSON.parse(match[0]));

  } catch (e) {
    console.error('Analyze error:', e);
    return res.status(500).json({ error: e.message });
  }
});

// Nmap scan - UNIQUE VERSION (supprimé le doublon)
app.post('/api/ai/nmap', auth, async (req, res) => {
  const { ip } = req.body;
  
  console.log('Nmap request received:', ip);

  if (!ip || ip.trim() === '') {
    return res.status(400).json({ error: "IP address required" });
  }

  const target = ip.trim();
  const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  
  if (!ipRegex.test(target)) {
    return res.status(400).json({ error: "Format IP invalide (ex: 192.168.1.1)" });
  }

  try {
    const scanOutput = execSync(`nmap -sV -T4 -F ${target}`, { 
      timeout: 60000,
      encoding: 'utf8'
    }).toString();
    
    console.log('Nmap completed for:', target);
    
    const openPorts = [];
    const lines = scanOutput.split('\n');
    for (const line of lines) {
      const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(.+)$/);
      if (portMatch) {
        openPorts.push({
          port: parseInt(portMatch[1]),
          protocol: portMatch[2],
          service: portMatch[3].trim()
        });
      }
    }
    
    let aiAnalysis = null;
    if (openPorts.length > 0) {
      try {
        const portsList = openPorts.map(p => `${p.port} (${p.service})`).join(', ');
        const aiPrompt = `Analyse ces ports ouverts sur ${target}: ${portsList}
        
Réponds STRICTEMENT en JSON:
{
  "risk_level": "critical|high|medium|low",
  "vulnerabilities": ["vuln1", "vuln2"],
  "recommendations": ["reco1", "reco2"]
}`;
        const aiResp = await callAI(aiPrompt);
        const match = aiResp.match(/\{[\s\S]*\}/);
        if (match) {
          aiAnalysis = JSON.parse(match[0]);
        }
      } catch (e) {
        console.error('AI analysis error:', e);
      }
    }
    
    res.json({
      target,
      open_ports: openPorts,
      risk_level: aiAnalysis?.risk_level || (openPorts.length > 5 ? 'high' : openPorts.length > 0 ? 'medium' : 'low'),
      vulnerabilities: aiAnalysis?.vulnerabilities || [],
      recommendations: aiAnalysis?.recommendations || [
        "Fermer les ports non nécessaires",
        "Mettre à jour les services exposés",
        "Configurer un pare-feu"
      ],
      raw_output: scanOutput.substring(0, 2000)
    });
    
  } catch (e) {
    console.error('Nmap execution error:', e.message);
    res.status(500).json({ 
      error: "Erreur lors du scan",
      details: e.message.includes("nmap: command not found") 
        ? "Nmap n'est pas installé sur le serveur" 
        : e.message
    });
  }
});

// ── Alert detection engine ────────────────────────────────────────────────────
async function detectAlerts() {
  try {
    const { rows: companies } = await pool.query('SELECT DISTINCT company_id FROM users');
    console.log(`Checking alerts for ${companies.length} companies...`);

    for (const { company_id } of companies) {
      let hits = [];
      try {
        const result = await es.search({
          index: `soc-logs-${company_id}-*`,
          size: 100,
          query: {
            bool: {
              must: [
                { exists: { field: 'alert_type' } },
                { range: { '@timestamp': { gte: 'now-1h' } } }
              ]
            }
          }
        });
        hits = result.hits.hits;
      } catch (e) {
        continue;
      }

      for (const hit of hits) {
        const src = hit._source;
        if (!src.alert_type || src.alert_type === 'system_event') continue;

        const existing = await pool.query(
          'SELECT id FROM alerts WHERE es_index=$1 AND company_id=$2',
          [hit._id, company_id]
        );
        if (existing.rows.length > 0) continue;

        const mitre = MITRE[src.alert_type] || null;
        
        let severity = src.severity || 'low';
        if (mitre?.severity) severity = mitre.severity;
        
        let mitreId = mitre?.id || null;
        let mitreName = mitre?.name || null;
        let mitreTactic = mitre?.tactic || null;

        const machineName = src.machine || src.host?.name || 'unknown';
        
        await pool.query(
          `INSERT INTO alerts
           (company_id, alert_type, severity, machine, message, es_index, 
            mitre_id, mitre_name, mitre_tactic)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [
            company_id,
            src.alert_type,
            severity,
            machineName,
            `${src.alert_type} detected on ${machineName}`,
            hit._id,
            mitreId,
            mitreName,
            mitreTactic
          ]
        );

        if (machineName && machineName !== 'unknown') {
          await pool.query(`
            INSERT INTO machines (company_id, name, ip, last_seen)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (company_id, name) DO UPDATE SET last_seen = NOW()
          `, [company_id, machineName, src.ip || null]).catch(() => {});
        }

        console.log(`[ALERT] ${company_id} | ${severity.toUpperCase()} | ${src.alert_type} on ${machineName}${mitreId ? ` | MITRE ${mitreId}` : ''}`);
      }
    }
  } catch (e) {
    console.error('Alert engine error:', e.message);
  }
}

setInterval(detectAlerts, 30000);
setTimeout(detectAlerts, 10000);
console.log('Alert detection engine started');

app.listen(3001, () => console.log('SOC API running on :3001'));