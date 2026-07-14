const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ─── OMNIROUTE CONFIG ──────────────────────────────────────
const OMNIROUTE_URL = 'https://omniroute-production-58df.up.railway.app/v1/chat/completions';
const OMNIROUTE_API_KEY = 'sk-8bbc294c5fb9e7a6-3a8865-7d998477';

// ─── SCANNER ENGINE ────────────────────────────────────────
function scanCode(code) {
  const issues = [];
  let integrity = 100;

  if (/JWT_SECRET\s*=\s*['"][^'"]+['"]/.test(code) ||
      /API_KEY\s*=\s*['"][^'"]+['"]/.test(code) ||
      /SECRET_KEY\s*=\s*['"][^'"]+['"]/.test(code)) {
    issues.push({
      severity: 'CRITICAL',
      type: 'Hardcoded Secret',
      message: 'API key or secret exposed in plain text.',
      fix: 'Move to environment variables.'
    });
    integrity -= 25;
  }

  if (/\$\{.*\}\s*(SELECT|INSERT|UPDATE|DELETE)/i.test(code) ||
      /db\.(query|execute)\s*\(['"][^'"]*['"]\s*\+/.test(code)) {
    issues.push({
      severity: 'CRITICAL',
      type: 'SQL Injection Risk',
      message: 'SQL query uses string concatenation. Vulnerable to injection.',
      fix: 'Use parameterized queries.'
    });
    integrity -= 25;
  }

  if (/catch\s*\([^)]*\)\s*\{\s*\}/.test(code)) {
    issues.push({
      severity: 'HIGH',
      type: 'Empty Catch Block',
      message: 'Catch block is empty. Errors are silently swallowed.',
      fix: 'Add error handling.'
    });
    integrity -= 20;
  }

  if (/useEffect\s*\(\s*\(?\s*\)?\s*=>\s*\{[^}]*\}\s*\)\s*;?\s*$/.test(code) &&
      !/useEffect\s*\([^)]*,\s*\[[^\]]*\]/.test(code)) {
    issues.push({
      severity: 'CRITICAL',
      type: 'Missing Dependency Array',
      message: 'useEffect called without dependency array. Causes infinite re-renders.',
      fix: 'Add [] as second argument.'
    });
    integrity -= 25;
  }

  if (/useEffect\s*\(/.test(code) &&
      !/import\s+React/.test(code) &&
      !/export\s+default\s+function/.test(code)) {
    issues.push({
      severity: 'CRITICAL',
      type: 'Server-side React Hook',
      message: 'useEffect used outside React component. Will crash Node.js.',
      fix: 'Remove useEffect or move to client-side.'
    });
    integrity -= 30;
  }

  if (/async\s+function/.test(code) && !/await/.test(code)) {
    issues.push({
      severity: 'HIGH',
      type: 'Missing Await',
      message: 'Async function called without await. Promise may not resolve.',
      fix: 'Add await.'
    });
    integrity -= 15;
  }

  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line && !line.endsWith(';') && !line.endsWith('{') && !line.endsWith('}') &&
        !line.startsWith('//') && !line.startsWith('/*') && !line.endsWith('(') &&
        !line.endsWith('=>') && !line.includes('import ') && !line.includes('export ') &&
        !line.includes('return ') && line.length > 5 && !line.includes('if') &&
        !line.includes('for') && !line.includes('while') && !line.includes('try') &&
        !line.includes('catch') && !line.includes('switch')) {
      issues.push({
        line: i + 1,
        severity: 'LOW',
        type: 'Missing Semicolon',
        message: 'Missing semicolon at end of line.',
        fix: 'Add `;` at the end of line ' + (i + 1)
      });
      integrity -= 2;
    }
  }

  const status = integrity < 30 ? 'CRITICAL' : integrity < 60 ? 'WARNING' : 'HEALTHY';

  return {
    integrity: Math.max(0, Math.min(100, integrity)),
    status: status,
    issues: issues,
    issueCount: issues.length
  };
}

// ─── AI REPAIR ─────────────────────────────────────────────
async function repairWithAI(code, issues) {
  const prompt = `
You are a code repair expert. Fix the following code issues:

${issues.map(i => `- ${i.type}: ${i.message}`).join('\n')}

Here is the code:
\`\`\`
${code}
\`\`\`

Return ONLY the fixed code. No explanations. Keep the same structure.
  `;

  try {
    const response = await fetch(OMNIROUTE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${OMNIROUTE_API_KEY}`
      },
      body: JSON.stringify({
        model: 'deepseek/deepseek-chat',
        messages: [
          { role: 'system', content: 'You are a code repair expert. Return only fixed code.' },
          { role: 'user', content: prompt }
        ],
        temperature: 0.3,
        max_tokens: 4000
      })
    });

    const data = await response.json();
    return data.choices[0].message.content;
  } catch (error) {
    console.error('AI repair failed:', error);
    return null;
  }
}

// ─── API ────────────────────────────────────────────────────

app.get('/', (req, res) => {
  res.json({ status: 'online', service: 'Unvulnify Engine' });
});

app.post('/api/scan', async (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ error: 'No code provided' });
  }

  const scanResult = scanCode(code);

  let fixedCode = null;
  if (scanResult.issues && scanResult.issues.length > 0) {
    const aiFix = await repairWithAI(code, scanResult.issues);
    if (aiFix) {
      fixedCode = aiFix;
    }
  }

  res.json({
    integrity: scanResult.integrity,
    status: scanResult.status,
    issues: scanResult.issues,
    fixedCode: fixedCode,
    message: fixedCode ? '✅ AI repair completed' : 'No fix generated',
    issueCount: scanResult.issues.length
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Unvulnify Engine running on port ${PORT}`);
});
