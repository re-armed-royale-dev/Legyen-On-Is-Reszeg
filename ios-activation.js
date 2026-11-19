
'use strict';

const crypto = require('crypto');
const net = require('net');

const sha256 = value =>
  crypto.createHash('sha256').update(String(value)).digest('hex');

const hashIp = (ip, secret) =>
  crypto.createHmac('sha256', secret).update(String(ip || 'unknown')).digest('hex');

const safeEqual = (a, b) => {
  const x = Buffer.from(String(a || ''), 'utf8');
  const y = Buffer.from(String(b || ''), 'utf8');
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

const bearer = req => {
  const match = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
  return match ? match[1].trim() : '';
};

function registerIosActivationRoutes(app, pool) {
  if (!pool) {
    throw new Error('Az iOS aktiváláshoz DATABASE_URL szükséges.');
  }

  const rateSecret = process.env.RATE_LIMIT_SECRET || '';
  const clientIp = req => req.ip || req.socket?.remoteAddress || 'unknown';

  const rateReady = (req, res, next) => {
    if (rateSecret.length < 32) {
      return res.status(503).json({
        success: false,
        error: 'A RATE_LIMIT_SECRET nincs megfelelően beállítva.'
      });
    }
    next();
  };

  // Próbálkozási állapot lekérdezése
  async function attemptStatus(ip) {
    const q = await pool.query(
      'SELECT failed_attempts, locked_until FROM public.license_attempts WHERE ip_hash=$1',
      [hashIp(ip, rateSecret)]
    );

    if (!q.rowCount) {
      return {
        failedAttempts: 0,
        remainingAttempts: 3,
        lockedUntil: null
      };
    }

    const row = q.rows[0];
    const until = row.locked_until
      ? new Date(row.locked_until)
      : null;

    if (until && until.getTime() > Date.now()) {
      return {
        failedAttempts: Number(row.failed_attempts) || 3,
        remainingAttempts: 0,
        lockedUntil: until.toISOString()
      };
    }

    if (until && until.getTime() <= Date.now()) {
      return {
        failedAttempts: 0,
        remainingAttempts: 3,
        lockedUntil: null
      };
    }

    const failed = Math.min(
      3,
      Math.max(0, Number(row.failed_attempts) || 0)
    );

    return {
      failedAttempts: failed,
      remainingAttempts: Math.max(0, 3 - failed),
      lockedUntil: null
    };
  }

  // Hibás próbálkozás rögzítése
  async function failAttempt(ip) {
    const client = await pool.connect();
    const ipHash = hashIp(ip, rateSecret);

    try {
      await client.query('BEGIN');

      await client.query(
        `INSERT INTO public.license_attempts
         (ip_hash, failed_attempts, updated_at)
         VALUES ($1, 0, NOW())
         ON CONFLICT (ip_hash) DO NOTHING`,
        [ipHash]
      );

      const q = await client.query(
        `SELECT failed_attempts, locked_until
         FROM public.license_attempts
         WHERE ip_hash=$1
         FOR UPDATE`,
        [ipHash]
      );

      const row = q.rows[0];
      const oldUntil = row.locked_until
        ? new Date(row.locked_until).getTime()
        : 0;

      if (oldUntil > Date.now()) {
        await client.query('COMMIT');

        return {
          locked: true,
          failedAttempts: Number(row.failed_attempts) || 3,
          remainingAttempts: 0,
          lockedUntil: new Date(oldUntil).toISOString()
        };
      }

      const fails = oldUntil
        ? 1
        : (Number(row.failed_attempts) || 0) + 1;

      const until = fails >= 3
        ? new Date(Date.now() + 30 * 86400000)
        : null;

      await client.query(
        `UPDATE public.license_attempts
         SET failed_attempts=$2,
             locked_until=$3,
             updated_at=NOW()
         WHERE ip_hash=$1`,
        [ipHash, fails, until]
      );

      await client.query('COMMIT');

      return {
        locked: Boolean(until),
        failedAttempts: fails,
        remainingAttempts: Math.max(0, 3 - fails),
        lockedUntil: until ? until.toISOString() : null
      };

    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  // ADMIN: egyszerű iOS feloldóoldal
  app.get('/admin/ios-unban', (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');

    res.type('html').send(`<!DOCTYPE html>
<html lang="hu">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iOS Admin – Tiltás feloldása</title>
<style>
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 20px;
  background: #0b0f19;
  color: white;
  font-family: Arial, sans-serif;
}
.panel {
  width: 100%;
  max-width: 420px;
  padding: 25px;
  border: 1px solid #374151;
  border-radius: 18px;
  background: #151c2b;
}
h2 { color: #fbbf24; margin-top: 0; }
p { color: #cbd5e1; }
label { display: block; margin-top: 12px; }
input {
  width: 100%;
  padding: 14px;
  margin: 8px 0 15px;
  border: 1px solid #475569;
  border-radius: 9px;
  background: #0b0f19;
  color: white;
  font-size: 16px;
}
button {
  width: 100%;
  padding: 15px;
  border: 0;
  border-radius: 9px;
  background: #dc2626;
  color: white;
  font-weight: bold;
  font-size: 16px;
  cursor: pointer;
}
button:disabled { opacity: .6; }
#result {
  margin-top: 18px;
  padding: 12px;
  border-radius: 8px;
  display: none;
  overflow-wrap: anywhere;
}
</style>
</head>
<body>
<div class="panel">
  <h2>🔐 iOS Admin</h2>
  <p>IP-cím tiltásának feloldása</p>

  <label>Admin API kulcs</label>
  <input id="adminKey" type="password"
    placeholder="Admin kulcs" autocomplete="off">

  <label>Feloldandó IP-cím</label>
  <input id="ip" type="text"
    placeholder="Például: 192.168.1.100"
    autocomplete="off">

  <button id="unlock" onclick="unban()">
    🔓 Tiltás feloldása
  </button>

  <div id="result"></div>
</div>

<script>
async function unban() {
  const key = document.getElementById('adminKey').value.trim();
  const ip = document.getElementById('ip').value.trim();
  const button = document.getElementById('unlock');
  const result = document.getElementById('result');

  result.style.display = 'block';

  if (!key || !ip) {
    result.textContent = 'Töltsd ki mindkét mezőt!';
    result.style.background = '#7f1d1d';
    return;
  }

  button.disabled = true;
  button.textContent = 'Feloldás folyamatban...';
  result.textContent = 'Kapcsolódás a szerverhez...';

  try {
    const response = await fetch('/api/admin/ios-unban', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + key
      },
      body: JSON.stringify({ ip })
    });

    const data = await response.json();

    result.textContent = data.message || data.error ||
      'Ismeretlen szerverválasz.';

    result.style.background =
      data.success && data.unbanned
        ? '#14532d'
        : '#7f1d1d';

    if (data.success && data.unbanned) {
      document.getElementById('ip').value = '';
    }

  } catch (error) {
    result.textContent =
      'Nem sikerült kapcsolódni a szerverhez.';
    result.style.background = '#7f1d1d';
  } finally {
    button.disabled = false;
    button.textContent = '🔓 Tiltás feloldása';
  }
}
</script>
</body>
</html>`);
  });

  // ADMIN: iOS tiltás feloldása
  app.post('/api/admin/ios-unban', rateReady, async (req, res) => {
    const adminKey = String(process.env.ADMIN_API_KEY || '');
    const suppliedKey = bearer(req);

    if (adminKey.length < 32) {
      return res.status(503).json({
        success: false,
        error: 'Az ADMIN_API_KEY nincs megfelelően beállítva.'
      });
    }

    if (!safeEqual(suppliedKey, adminKey)) {
      return res.status(401).json({
        success: false,
        error: 'Nincs adminisztrátori jogosultság.'
      });
    }

    const ip = String(req.body?.ip || '').trim();

    if (!net.isIP(ip)) {
      return res.status(400).json({
        success: false,
        error: 'Érvénytelen IP-cím.'
      });
    }

    try {
      const result = await pool.query(
        'DELETE FROM public.license_attempts WHERE ip_hash=$1',
        [hashIp(ip, rateSecret)]
      );

      res.setHeader('Cache-Control', 'no-store');

      return res.json({
        success: true,
        unbanned: result.rowCount > 0,
        message: result.rowCount > 0
          ? 'A tiltás sikeresen feloldva.'
          : 'Ehhez az IP-címhez nem található tiltás.'
      });

    } catch (error) {
      console.error('iOS admin unban:', error);

      return res.status(500).json({
        success: false,
        error: 'A tiltás feloldása nem sikerült.'
      });
    }
  });

  // Próbálkozási állapot
  app.get('/api/ios/attempt-status', rateReady, async (req, res) => {
    try {
      res.setHeader('Cache-Control', 'no-store');

      res.json({
        success: true,
        ...await attemptStatus(clientIp(req))
      });

    } catch (error) {
      console.error('iOS attempt status:', error);

      res.status(500).json({
        success: false,
        error: 'Nem sikerült lekérdezni a próbálkozási állapotot.'
      });
    }
  });

  // iOS aktiválás
  app.post('/api/ios/activate', rateReady, async (req, res) => {
    const submittedKey = String(req.body?.activationKey || '').trim();
    const installId = String(req.body?.installId || '');
    const serverKey = String(process.env.IOS_ACTIVATE_KEY || '');

    if (!/^\d{12}$/.test(serverKey)) {
      return res.status(503).json({
        success: false,
        error: 'Az iOS aktiválókulcs nincs megfelelően beállítva a szerveren.'
      });
    }

    if (
      !/^\d{12}$/.test(submittedKey) ||
      !/^[A-F0-9-]{20,80}$/i.test(installId)
    ) {
      return res.status(400).json({
        success: false,
        error: 'Érvénytelen kulcs vagy eszközazonosító.'
      });
    }

    try {
      const ip = clientIp(req);
      const status = await attemptStatus(ip);

      if (status.lockedUntil) {
        return res.status(429).json({
          success: false,
          error: 'Három hibás próbálkozás miatt 30 napos tiltás van érvényben.',
          ...status
        });
      }

      if (!safeEqual(submittedKey, serverKey)) {
        const attempt = await failAttempt(ip);

        return res.status(attempt.locked ? 429 : 401).json({
          success: false,
          error: attempt.locked
            ? 'Három hibás próbálkozás miatt 30 napos tiltás lépett életbe.'
            : 'Hibás aktiválókulcs.',
          ...attempt
        });
      }

      const token = crypto.randomBytes(32).toString('hex');

      await pool.query(
        `INSERT INTO public.ios_activation_sessions
         (install_id, token_hash, created_at, last_seen_at, active)
         VALUES ($1, $2, NOW(), NOW(), TRUE)
         ON CONFLICT (install_id)
         DO UPDATE SET
           token_hash=EXCLUDED.token_hash,
           last_seen_at=NOW(),
           active=TRUE`,
        [installId, sha256(token)]
      );

      await pool.query(
        'DELETE FROM public.license_attempts WHERE ip_hash=$1',
        [hashIp(ip, rateSecret)]
      );

      res.setHeader('Cache-Control', 'no-store');
      res.json({ success: true, token });

    } catch (error) {
      console.error('iOS activation:', error);

      res.status(500).json({
        success: false,
        error: 'Az aktiválás most nem sikerült.'
      });
    }
  });

  // Aktiválási állapot ellenőrzése
  app.get('/api/ios/status', async (req, res) => {
    const token = bearer(req);

    if (!token || token.length > 200) {
      return res.status(401).json({
        success: false,
        active: false
      });
    }

    try {
      const q = await pool.query(
        `SELECT id
         FROM public.ios_activation_sessions
         WHERE token_hash=$1 AND active=TRUE
         LIMIT 1`,
        [sha256(token)]
      );

      if (!q.rowCount) {
        return res.status(401).json({
          success: false,
          active: false
        });
      }

      await pool.query(
        'UPDATE public.ios_activation_sessions SET last_seen_at=NOW() WHERE id=$1',
        [q.rows[0].id]
      );

      res.setHeader('Cache-Control', 'no-store');

      res.json({
        success: true,
        active: true
      });

    } catch (error) {
      console.error('iOS activation status:', error);

      res.status(500).json({
        success: false,
        active: false
      });
    }
  });
}

async function initializeIosActivationTables(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.ios_activation_sessions (
      id BIGSERIAL PRIMARY KEY,
      install_id VARCHAR(80) NOT NULL UNIQUE,
      token_hash CHAR(64) NOT NULL UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      active BOOLEAN NOT NULL DEFAULT TRUE
    )
  `);

  console.log('iOS aktiválási adatbázistábla ellenőrizve!');
}

module.exports = {
  registerIosActivationRoutes,
  initializeIosActivationTables
};
