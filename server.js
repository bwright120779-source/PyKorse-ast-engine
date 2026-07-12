const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ─── SCANNER ENGINE ────────────────────────────────────────
function scanCode(code) {
  const issues = [];
  let integrity = 100;

  // RULE 1: Hardcoded secrets
  if (/JWT_SECRET\s*=\s*['"][^'"]+['"]/.test(code) ||
      /API_KEY\s*=\s*['"][^'"]+['"]/.test(code) ||
      /SECRET_KEY\s*=\s*['"][^'"]+['"]/.test(code)) {
    issues.push({
      severity: 'CRITICAL',
      type: 'Hardcoded Secret',
      message: 'API key or secret exposed in plain text.',
      fix: 'Move to environment variables: `const SECRET = process.env.SECRET;`'
    });
    integrity -= 25;
  }

  // RULE 2: SQL injection
  if (/\$\{.*\}\s*(SELECT|INSERT|UPDATE|DELETE)/i.test(code) ||
      /db\.(query|execute)\s*\(['"][^'"]*['"]\s*\+/.test(code)) {
    issues.push({
      severity: 'CRITICAL',
      type: 'SQL Injection Risk',
      message: 'SQL query uses string concatenation. Vulnerable to injection.',
      fix: 'Use parameterized queries: `db.query("SELECT * FROM users WHERE id = ?", [userId])`'
    });
    integrity -= 25;
  }

  // RULE 3: Empty catch block
  if (/catch\s*\([^)]*\)\s*\{\s*\}/.test(code)) {
    issues.push({
      severity: 'HIGH',
      type: 'Empty Catch Block',
      message: 'Catch block is empty. Errors are silently swallowed.',
      fix: 'Add error handling: `catch (err) { console.error(err); throw err; }`'
    });
    integrity -= 20;
  }

  // RULE 4: useEffect without dependencies
  if (/useEffect\s*\(\s*\(?\s*\)?\s*=>\s*\{[^}]*\}\s*\)\s*;?\s*$/.test(code) &&
      !/useEffect\s*\([^)]*,\s*\[[^\]]*\]/.test(code)) {
    issues.push({
      severity: 'CRITICAL',
      type: 'Missing Dependency Array',
      message: 'useEffect called without dependency array. Causes infinite re-renders.',
      fix: 'Add [] as second argument: `useEffect(() => {...}, []);`'
    });
    integrity -= 25;
  }

  // RULE 5: Server-side useEffect
  if (/useEffect\s*\(/.test(code) &&
      !/import\s+React/.test(code) &&
      !/export\s+default\s+function/.test(code)) {
    issues.push({
      severity: 'CRITICAL',
      type: 'Server-side React Hook',
      message: 'useEffect used outside React component. Will crash Node.js.',
      fix: 'Remove useEffect or move to client-side React component.'
    });
    integrity -= 30;
  }

  // RULE 6: Missing await
  if (/async\s+function/.test(code) && !/await/.test(code)) {
    issues.push({
      severity: 'HIGH',
      type: 'Missing Await',
      message: 'Async function called without await. Promise may not resolve.',
      fix: 'Add await: `await functionName()`'
    });
    integrity -= 15;
  }

  // RULE 7: Missing semicolons
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

  // ─── GENERATE FIX ────────────────────────────────────────
  let fixedCode = code;
  if (issues.some(i => i.type === 'Hardcoded Secret')) {
    fixedCode = fixedCode.replace(/(const\s*(?:JWT_SECRET|API_KEY|SECRET_KEY)\s*=\s*['"])[^'"]+(['"])/gi, '$1process.env.$2$3');
  }
  if (issues.some(i => i.type === 'Missing Dependency Array')) {
    fixedCode = fixedCode.replace(/(useEffect\s*\([^)]*\))\s*;?/g, '$1, []);');
  }
  if (issues.some(i => i.type === 'Empty Catch Block')) {
    fixedCode = fixedCode.replace(/catch\s*\([^)]*\)\s*\{\s*\}/g, 'catch (err) {\n    console.error("Error caught:", err);\n    throw err;\n  }');
  }

  const status = integrity < 30 ? 'CRITICAL' : integrity < 60 ? 'WARNING' : 'HEALTHY';

  return {
    integrity: Math.max(0, Math.min(100, integrity)),
    status: status,
    issues: issues,
    fixedCode: fixedCode !== code ? fixedCode : null,
    message: fixedCode !== code ? '✅ Fix generated. Review and deploy.' : 'No fix generated. Manual review needed.',
    issueCount: issues.length
  };
}

// ─── API ENDPOINTS ─────────────────────────────────────────

app.get('/', (req, res) => {
  res.json({ status: 'online', service: 'Cerberus Engine' });
});

app.post('/api/scan', (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ error: 'No code provided' });
  }
  try {
    const result = scanCode(code);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Cerberus Engine running on port ${PORT}`);
});
