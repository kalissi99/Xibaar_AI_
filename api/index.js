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
const JWT_SECRET = process.env.JWT_SECRET;

// ── Auth middleware ──────────────────────────────────────────────────────────
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

// ── DB setup ─────────────────────────────────────────────────────────────────
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
          created_at TIMESTAMP DEFAULT NOW(),
          acknowledged BOOLEAN DEFAULT FALSE
        );
      `);
      console.log('Database ready');
      return;
    } catch (e) {
      console.log(`DB not ready, retrying... (${retries} left)`);
      retries--;
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  console.error('Could not connect to database');
}

initDB();
// ── Routes ───────────────────────────────────────────────────────────────────

// Register (first user = admin, keep this endpoint private in production)
app.post('/api/register', async (req, res) => {
  const { email, password, company_id } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
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
  const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Bad credentials' });
  const token = jwt.sign({ id: user.id, company_id: user.company_id, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, company_id: user.company_id });
});

// Get recent alerts for this company
app.get('/api/alerts', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM alerts WHERE company_id=$1 ORDER BY created_at DESC LIMIT 100',
    [req.user.company_id]
  );
  res.json(rows);
});

// Acknowledge an alert
app.patch('/api/alerts/:id/ack', auth, async (req, res) => {
  await pool.query('UPDATE alerts SET acknowledged=TRUE WHERE id=$1 AND company_id=$2', [req.params.id, req.user.company_id]);
  res.json({ ok: true });
});

// Live log search from Elasticsearch
app.get('/api/logs', auth, async (req, res) => {
  const { severity, type, size = 50 } = req.query;
  const must = [{ match: { company_id: req.user.company_id } }];
  if (severity) must.push({ match: { severity } });
  if (type) must.push({ match: { alert_type: type } });
  try {
    const result = await es.search({
      index: `soc-logs-${req.user.company_id}-*`,
      size: parseInt(size),
      sort: [{ '@timestamp': { order: 'desc' } }],
      query: { bool: { must } }
    });
    res.json(result.hits.hits.map(h => h._source));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Dashboard summary stats
app.get('/api/stats', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT severity, COUNT(*) as count
    FROM alerts
    WHERE company_id=$1 AND created_at > NOW() - INTERVAL '24 hours'
    GROUP BY severity
  `, [req.user.company_id]);
  res.json(rows);
});

// ── AI Agent ─────────────────────────────────────────────────────────────────

// Helper: call Gemini API
async function callGemini(prompt) {
  const GEMINI_KEY = process.env.GEMINI_API_KEY;
  const body = JSON.stringify({
    contents: [{ parts: [{ text: prompt }] }]
  });

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'generativelanguage.googleapis.com',
      path: `/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_KEY}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json.candidates?.[0]?.content?.parts?.[0]?.text || 'No response');
        } catch { resolve('Error parsing Gemini response'); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

app.post('/api/ai/analyze', auth, async (req, res) => {
  try {
    const { rows: recentAlerts } = await pool.query(
      `SELECT alert_type, severity, machine, message, created_at
       FROM alerts
       WHERE company_id=$1
       ORDER BY created_at DESC
       LIMIT 20`,
      [req.user.company_id]
    );

    if (recentAlerts.length === 0) {
      return res.json({ analysis: 'No recent incidents found for analysis.', recommendations: [], risk_level: 'low' });
    }

    const alertSummary = recentAlerts.map(a =>
      `- [${a.severity.toUpperCase()}] ${a.alert_type} on machine "${a.machine}" at ${a.created_at}: ${a.message || 'no details'}`
    ).join('\n');

    const prompt = `You are a cybersecurity analyst reviewing security incidents for a small/medium business.

Here are the latest security events detected:
${alertSummary}

Please provide:
1. RISK LEVEL: (critical/high/medium/low) - overall risk assessment
2. SUMMARY: 2-3 sentence summary of what is happening
3. THREATS DETECTED: List each unique threat type found
4. IMMEDIATE ACTIONS: Top 3 things to do RIGHT NOW
5. RECOMMENDATIONS: 5 specific security recommendations to prevent recurrence
6. EXPLANATION: Explain each alert type in simple terms for a non-technical business owner

Format your response as JSON with these exact keys:
{
  "risk_level": "high",
  "summary": "...",
  "threats": ["threat1", "threat2"],
  "immediate_actions": ["action1", "action2", "action3"],
  "recommendations": ["rec1", "rec2", "rec3", "rec4", "rec5"],
  "explanation": "..."
}`;

    const raw = await callGemini(prompt);

    // Extract JSON from response
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      res.json(parsed);
    } else {
      res.json({ risk_level: 'unknown', summary: raw, threats: [], immediate_actions: [], recommendations: [], explanation: '' });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Run Nmap scan on a machine IP
app.post('/api/ai/nmap', auth, async (req, res) => {
  const { ip, machine } = req.body;
  if (!ip && !machine) return res.status(400).json({ error: 'IP or machine name required' });

  const target = ip || machine;

  // Basic validation — prevent command injection
  if (!/^[a-zA-Z0-9.\-_]+$/.test(target)) {
    return res.status(400).json({ error: 'Invalid target' });
  }

  try {
    let nmapResult;
    try {
      nmapResult = execSync(`nmap -sV -T4 --top-ports 100 ${target} 2>&1`, { timeout: 60000 }).toString();
    } catch (e) {
      nmapResult = e.stdout?.toString() || 'Nmap not available or scan failed';
    }

    // Send nmap results to Gemini for analysis
    const prompt = `You are a cybersecurity analyst. Here are Nmap scan results for machine "${target}":

${nmapResult}

Please analyze these results and provide:
1. OPEN PORTS: List all open ports and what services are running
2. VULNERABILITIES: Any concerning open ports or services that could be exploited
3. RISK ASSESSMENT: Overall risk level of this machine
4. RECOMMENDATIONS: Specific steps to secure this machine

Format as JSON:
{
  "open_ports": [{"port": "22", "service": "SSH", "risk": "medium"}],
  "vulnerabilities": ["vuln1", "vuln2"],
  "risk_level": "medium",
  "recommendations": ["rec1", "rec2", "rec3"],
  "raw_output": "..."
}`;

    const analysis = await callGemini(prompt);
    const jsonMatch = analysis.match(/\{[\s\S]*\}/);

    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      parsed.raw_output = nmapResult;
      res.json(parsed);
    } else {
      res.json({ risk_level: 'unknown', open_ports: [], vulnerabilities: [], recommendations: [], raw_output: nmapResult, analysis });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/network/scan', auth, async (req, res) => {
  const cidr = req.body.cidr || "192.168.1.0/24";

  try {
    const output = execSync(`nmap -sn ${cidr}`).toString();

    res.json({
      scan_time: new Date(),
      raw: output
    });

  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Chat with AI about your SOC
app.post('/api/ai/chat', auth, async (req, res) => {
  const { message, history } = req.body;

  const { rows: recentAlerts } = await pool.query(
    `SELECT alert_type, severity, machine, created_at FROM alerts WHERE company_id=$1 ORDER BY created_at DESC LIMIT 10`,
    [req.user.company_id]
  );

  const context = recentAlerts.map(a => `${a.alert_type} (${a.severity}) on ${a.machine}`).join(', ');

  const conversationHistory = (history || []).map(h => `${h.role}: ${h.content}`).join('\n');

  const prompt = `You are a cybersecurity assistant for a SOC platform. You help analysts understand and respond to security incidents.

Current security context for this company:
Recent alerts: ${context || 'none'}

Previous conversation:
${conversationHistory}

Analyst asks: ${message}

Respond helpfully and concisely. If asked about specific threats, explain them clearly. If asked for commands or steps, provide them.`;

  try {
    const response = await callGemini(prompt);
    res.json({ response });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


app.post('/api/logs/ingest', async (req, res) => {
  const log = req.body;

  // extract machine
  const machine = log.host?.name || log.machine || log.agent?.name;

  if (machine) {
    await pool.query(`
      INSERT INTO machines (company_id, name, ip, last_seen)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT DO NOTHING
    `, [log.company_id, machine, log.ip || null]);
  }

  res.json({ ok: true });
});


app.get('/api/machines', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM machines WHERE company_id=$1 ORDER BY last_seen DESC',
    [req.user.company_id]
  );
  res.json(rows);
});

// ── Alert detection engine ────────────────────────────────────────────────
async function detectAlerts() {
  try {
    // Get all company IDs from users table
    const { rows: companies } = await pool.query('SELECT DISTINCT company_id FROM users');

    for (const { company_id } of companies) {
      try {
        // Search Elasticsearch for events in last 2 minutes
        const result = await es.search({
          index: `soc-logs-${company_id}-*`,
          size: 100,
          query: {
            bool: {
              must: [
                { match: { company_id } },
                { exists: { field: 'alert_type' } },
                { range: { '@timestamp': { gte: 'now-2m' } } }
              ],
              must_not: [
                { match: { alert_type: 'system_event' } }
              ]
            }
          }
        });

        const hits = result.hits.hits;

        for (const hit of hits) {
          const src = hit._source;
          const alertType = src.alert_type;
          const severity  = src.severity;
          const machine   = src.machine || src.host?.name || 'unknown';
          const esId      = hit._id;

          if (!alertType || alertType === 'system_event') continue;

          // Check if we already inserted this ES document
          const existing = await pool.query(
            'SELECT id FROM alerts WHERE es_index=$1 AND company_id=$2',
            [esId, company_id]
          );

          if (existing.rows.length === 0) {
            await pool.query(
              `INSERT INTO alerts (company_id, alert_type, severity, machine, message, es_index)
               VALUES ($1, $2, $3, $4, $5, $6)`,
              [
                company_id,
                alertType,
                severity,
                machine,
                `${alertType} detected on ${machine}`,
                esId
              ]
            );
            console.log(`[ALERT] ${severity.toUpperCase()} - ${alertType} on ${machine} (${company_id})`);
          }
        }
      } catch (e) {
        // Index might not exist yet for this company
        if (!e.message?.includes('index_not_found')) {
          console.error(`Alert detection error for ${company_id}:`, e.message);
        }
      }
    }
  } catch (e) {
    console.error('Alert engine error:', e.message);
  }
}

// Run alert detection every 30 seconds
setInterval(detectAlerts, 30000);
// Also run immediately on startup after 10s delay
setTimeout(detectAlerts, 10000);
console.log('Alert detection engine started');

app.listen(3001, () => console.log('SOC API running on :3001'));