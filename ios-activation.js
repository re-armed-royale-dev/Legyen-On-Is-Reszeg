
'use strict';

const crypto = require('crypto');
const net = require('net');

const sha256 = value =>
  crypto.createHash('sha256').update(String(value)).digest('hex');

const hashIp = (ip, secret) =>
  crypto.createHmac('sha256', secret)
    .update(String(ip || 'unknown'))
    .digest('hex');

// IP-cím titkosítása AES-256-GCM módszerrel
function encryptIp(ip, secret) {
  const key = crypto.createHash('sha256')
    .update('ios-ip-encryption:' + secret)
    .digest();

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([
    cipher.update(String(ip), 'utf8'),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return [
    iv.toString('hex'),
    tag.toString('hex'),
    encrypted.toString('hex')
  ].join(':');
}

// Titkosított IP visszafejtése
function decryptIp(value, secret) {
  try {
    if (!value) return null;

    const parts = String(value).split(':');
    if (parts.length !== 3) return null;

    const [ivHex, tagHex, encryptedHex] = parts;

    const key = crypto.createHash('sha256')
      .update('ios-ip-encryption:' + secret)
      .digest();

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(ivHex, 'hex')
    );

    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedHex, 'hex')),
      decipher.final()
    ]);

    return decrypted.toString('utf8');
  } catch {
    return null;
  }
}

const safeEqual = (a, b) => {
  const x = Buffer.from(String(a || ''), 'utf8');
  const y = Buffer.from(String(b || ''), 'utf8');

  return x.length === y.length &&
    crypto.timingSafeEqual(x, y);
};

const bearer = req => {
  const match = /^Bearer\s+(.+)$/i.exec(
    req.headers.authorization || ''
  );

  return match ? match[1].trim() : '';
};

function registerIosActivationRoutes(app, pool) {
  if (!pool) {
    throw new Error('Az iOS aktiváláshoz DATABASE_URL szükséges.');
  }

  const rateSecret = process.env.RATE_LIMIT_SECRET || '';

  const clientIp = req =>
    req.ip || req.socket?.remoteAddress || 'unknown';

  const rateReady = (req, res, next) => {
    if (rateSecret.length < 32) {
      return res.status(503).json({
        success: false,
        error: 'A RATE_LIMIT_SECRET nincs megfelelően beállítva.'
      });
    }

    next();
  };

  // Admin jogosultság ellenőrzése
  function checkAdmin(req, res) {
    const adminKey = String(process.env.ADMIN_API_KEY || '');
    const suppliedKey = bearer(req);

    if (adminKey.length < 32) {
      res.status(503).json({
        success: false,
        error: 'Az ADMIN_API_KEY nincs megfelelően beállítva.'
      });

      return false;
    }

    if (!safeEqual(suppliedKey, adminKey)) {
      res.status(401).json({
        success: false,
        error: 'Nincs adminisztrátori jogosultság.'
      });

      return false;
    }

    return true;
  }

  // Próbálkozási állapot lekérdezése
  async function attemptStatus(ip) {
    const q = await pool.query(
      `SELECT failed_attempts, locked_until
       FROM public.license_attempts
       WHERE ip_hash=$1`,
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
    const encryptedIp = encryptIp(ip, rateSecret);

    try {
      await client.query('BEGIN');

      await client.query(
        `INSERT INTO public.license_attempts
         (ip_hash, failed_attempts, updated_at, ip_encrypted)
         VALUES ($1, 0, NOW(), $2)
         ON CONFLICT (ip_hash)
         DO UPDATE SET
           ip_encrypted = COALESCE(
             public.license_attempts.ip_encrypted,
             EXCLUDED.ip_encrypted
           )`,
        [ipHash, encryptedIp]
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
             updated_at=NOW(),
             ip_encrypted=$4
         WHERE ip_hash=$1`,
        [ipHash, fails, until, encryptedIp]
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

  // ADMIN: feloldóoldal
  app.get('/admin/ios-unban', (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');

    res.type('html').send(`<!DOCTYPE html>
<html lang="hu">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iOS Admin</title>
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
  max-width: 500px;
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
  padding: 14px;
  border: 0;
  border-radius: 9px;
  background: #dc2626;
  color: white;
  font-weight: bold;
  font-size: 15px;
  cursor: pointer;
}
button:disabled { opacity: .6; }
.secondary {
  background: #334155;
  margin-bottom: 12px;
}
#result {
  margin-top: 15px;
  padding: 12px;
  border-radius: 8px;
  display: none;
  overflow-wrap: anywhere;
}
#banList { margin-top: 15px; }
.ban {
  border: 1px solid #475569;
  border-radius: 10px;
  padding: 13px;
  margin-top: 10px;
  background: #0b0f19;
  overflow-wrap: anywhere;
}
.ban button { margin-top: 10px; }
.small {
  color: #94a3b8;
  font-size: 13px;
  line-height: 1.5;
}
hr {
  border: 0;
  border-top: 1px solid #374151;
  margin: 22px 0;
}
</style>
</head>
<body>
<div class="panel">
  <h2>🔐 iOS Admin</h2>
  <p>iOS aktiválási tiltások kezelése</p>

  <label>Admin API kulcs</label>
  <input id="adminKey" type="password"
    placeholder="Admin kulcs" autocomplete="off">

  <button class="secondary" onclick="loadBans()">
    📋 Tiltott IP-címek betöltése
  </button>

  <div id="result"></div>
  <div id="banList"></div>

  <hr>

  <h3>➕ Kézi feloldás</h3>
  <label>IP-cím</label>
  <input id="ip" type="text"
    placeholder="Például: 192.168.1.100" autocomplete="off">

  <button onclick="manualUnban()">🔓 Tiltás feloldása</button>

  <button class="secondary" onclick="unbanCurrentIp()">
    🔓 Saját aktuális IP-címem feloldása
  </button>

  <p class="small">
    Az IP-címek titkosítva vannak tárolva.
    Csak admin jogosultsággal jeleníthetők meg.
  </p>
</div>

<script>
function getKey() {
  return document.getElementById('adminKey').value.trim();
}

function showResult(message, success) {
  const result = document.getElementById('result');
  result.style.display = 'block';
  result.textContent = message;
  result.style.background = success ? '#14532d' : '#7f1d1d';
}

async function api(url, options = {}) {
  const headers = {
    'Authorization': 'Bearer ' + getKey(),
    ...options.headers
  };

  return fetch(url, { ...options, headers });
}

async function loadBans() {
  if (!getKey()) {
    showResult('Először add meg az admin API kulcsot!', false);
    return;
  }

  const list = document.getElementById('banList');
  list.textContent = 'Tiltások betöltése...';

  try {
    const response = await api('/api/admin/ios-bans');
    const data = await response.json();

    if (!response.ok || !data.success) {
      list.textContent = '';
      showResult(data.error || 'Nem sikerült betölteni a listát.', false);
      return;
    }

    list.textContent = '';

    if (!data.bans.length) {
      list.textContent = 'Jelenleg nincs aktív, megjeleníthető tiltás.';
      showResult('A lista sikeresen betöltve.', true);
      return;
    }

    data.bans.forEach(ban => {
      const card = document.createElement('div');
      card.className = 'ban';

      const ip = document.createElement('strong');
      ip.textContent = 'IP: ' + ban.ip;

      const attempts = document.createElement('div');
      attempts.textContent =
        'Hibás próbálkozások: ' + ban.failedAttempts;

      const until = document.createElement('div');
      until.textContent =
        'Tiltás lejárata: ' +
        new Date(ban.lockedUntil).toLocaleString('hu-HU');

      const button = document.createElement('button');
      button.textContent = '🔓 IP feloldása';
      button.onclick = () => unbanIp(ban.ip);

      card.append(ip, attempts, until, button);
      list.appendChild(card);
    });

    showResult('Betöltve: ' + data.bans.length + ' aktív tiltás.', true);

  } catch (error) {
    list.textContent = '';
    showResult('Kapcsolódási hiba a szerverrel.', false);
  }
}

async function unbanIp(ip) {
  if (!confirm('Biztosan feloldod ezt az IP-címet: ' + ip + '?')) {
    return;
  }

  try {
    const response = await api('/api/admin/ios-unban', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });

    const data = await response.json();

    showResult(
      data.message || data.error || 'Szerverválasz érkezett.',
      data.success && data.unbanned
    );

    if (data.success && data.unbanned) await loadBans();

  } catch (error) {
    showResult('Nem sikerült kapcsolódni a szerverhez.', false);
  }
}

async function unbanCurrentIp() {
  if (!getKey()) {
    showResult('Először add meg az admin API kulcsot!', false);
    return;
  }

  if (!confirm('Biztosan feloldod azt az IP-címet, amelyet a szerver most érzékel?')) {
    return;
  }

  try {
    const response = await api('/api/admin/ios-unban-current', {
      method: 'POST'
    });

    const data = await response.json();

    showResult(
      data.message || data.error || 'Szerverválasz érkezett.',
      data.success && data.unbanned
    );

    if (data.success && data.unbanned) await loadBans();

  } catch (error) {
    showResult('Nem sikerült kapcsolódni a szerverhez.', false);
  }
}

async function manualUnban() {
  const ip = document.getElementById('ip').value.trim();

  if (!ip) {
    showResult('Írd be a feloldandó IP-címet!', false);
    return;
  }

  await unbanIp(ip);
  document.getElementById('ip').value = '';
}
</script>
</body>
</html>`);
  });

  // ADMIN: aktív tiltások listázása
  app.get('/api/admin/ios-bans', rateReady, async (req, res) => {
    if (!checkAdmin(req, res)) return;

    try {
      const result = await pool.query(
        `SELECT ip_encrypted, failed_attempts, locked_until
         FROM public.license_attempts
         WHERE locked_until > NOW()
           AND ip_encrypted IS NOT NULL
         ORDER BY locked_until DESC
         LIMIT 500`
      );

      const bans = result.rows
        .map(row => ({
          ip: decryptIp(row.ip_encrypted, rateSecret),
          failedAttempts: Number(row.failed_attempts) || 0,
          lockedUntil: new Date(row.locked_until).toISOString()
        }))
        .filter(row => row.ip && net.isIP(row.ip));

      res.setHeader('Cache-Control', 'no-store');

      return res.json({ success: true, bans });

    } catch (error) {
      console.error('iOS admin ban list:', error);

      return res.status(500).json({
        success: false,
        error: 'A tiltáslista betöltése nem sikerült.'
      });
    }
  });

  // ADMIN: iOS tiltás feloldása IP alapján
  app.post('/api/admin/ios-unban', rateReady, async (req, res) => {
    if (!checkAdmin(req, res)) return;

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

  // Aktuális kérés IP-címének feloldása
  app.post('/api/admin/ios-unban-current', rateReady, async (req, res) => {
    if (!checkAdmin(req, res)) return;

    try {
      const ip = clientIp(req);

      if (!net.isIP(ip)) {
        return res.status(400).json({
          success: false,
          error: 'A szerver nem tudott érvényes IP-címet azonosítani.'
        });
      }

      const result = await pool.query(
        'DELETE FROM public.license_attempts WHERE ip_hash=$1',
        [hashIp(ip, rateSecret)]
      );

      res.setHeader('Cache-Control', 'no-store');

      return res.json({
        success: true,
        unbanned: result.rowCount > 0,
        message: result.rowCount > 0
          ? 'A szerver által érzékelt IP-cím tiltása feloldva.'
          : 'Ehhez az IP-címhez nem található tiltás.'
      });

    } catch (error) {
      console.error('iOS current IP unban:', error);

      return res.status(500).json({
        success: false,
        error: 'A feloldás nem sikerült.'
      });
    }
  });

  // Próbálkozási állapot és biztonságos IP-azonosító
  app.get('/api/ios/attempt-status', rateReady, async (req, res) => {
    try {
      const ip = clientIp(req);
      const ipTag = hashIp(ip, rateSecret).slice(0, 12);

      res.setHeader('Cache-Control', 'no-store');

      return res.json({
        success: true,
        ...await attemptStatus(ip),
        ipTag
      });

    } catch (error) {
      console.error('iOS attempt status:', error);

      return res.status(500).json({
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
      return res.json({ success: true, token });

    } catch (error) {
      console.error('iOS activation:', error);

      return res.status(500).json({
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

      return res.json({
        success: true,
        active: true
      });

    } catch (error) {
      console.error('iOS activation status:', error);

      return res.status(500).json({
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

  await pool.query(`
    ALTER TABLE public.license_attempts
    ADD COLUMN IF NOT EXISTS ip_encrypted TEXT
  `);

  console.log('iOS aktiválási és IP-titkosítási adatbázis ellenőrizve!');
}

module.exports = {
  registerIosActivationRoutes,
  initializeIosActivationTables
};
