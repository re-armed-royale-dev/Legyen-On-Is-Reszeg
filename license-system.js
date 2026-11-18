'use strict';
const crypto = require('crypto');

const sha256 = value => crypto.createHash('sha256').update(String(value)).digest('hex');
const normalizeKey = value => String(value || '').toUpperCase().replace(/[^A-F0-9]/g, '');
const hashIp = (ip, secret) => crypto.createHmac('sha256', secret).update(String(ip || 'unknown')).digest('hex');
const bearer = req => {
  const match = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
  return match ? match[1].trim() : '';
};
const safeEqual = (a, b) => {
  const x = Buffer.from(String(a || ''));
  const y = Buffer.from(String(b || ''));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

function registerLicenseRoutes(app, pool) {
  if (!pool) throw new Error('A licencrendszerhez DATABASE_URL szükséges.');
  const rateSecret = process.env.RATE_LIMIT_SECRET || '';
  const adminKey = process.env.ADMIN_API_KEY || '';
  const clientIp = req => req.ip || req.socket?.remoteAddress || 'unknown';

  const rateReady = (req, res, next) => {
    if (rateSecret.length < 32) return res.status(503).json({ success: false, error: 'A RATE_LIMIT_SECRET nincs beállítva.' });
    next();
  };
  const adminOnly = (req, res, next) => {
    if (adminKey.length < 32) return res.status(503).json({ success: false, error: 'Az ADMIN_API_KEY nincs beállítva.' });
    if (!safeEqual(req.headers['x-admin-api-key'], adminKey)) return res.status(401).json({ success: false, error: 'Nincs jogosultság.' });
    next();
  };

  async function attemptStatus(ip) {
    const q = await pool.query('SELECT failed_attempts, locked_until FROM public.license_attempts WHERE ip_hash=$1', [hashIp(ip, rateSecret)]);
    if (!q.rowCount) return { failedAttempts: 0, remainingAttempts: 3, lockedUntil: null };
    const row = q.rows[0];
    const until = row.locked_until ? new Date(row.locked_until) : null;
    if (until && until.getTime() > Date.now()) return { failedAttempts: Number(row.failed_attempts) || 3, remainingAttempts: 0, lockedUntil: until.toISOString() };
    return { failedAttempts: 0, remainingAttempts: 3, lockedUntil: null };
  }

  async function failAttempt(ip) {
    const client = await pool.connect();
    const ipHash = hashIp(ip, rateSecret);
    try {
      await client.query('BEGIN');
      await client.query('INSERT INTO public.license_attempts (ip_hash,failed_attempts,updated_at) VALUES ($1,0,NOW()) ON CONFLICT (ip_hash) DO NOTHING', [ipHash]);
      const q = await client.query('SELECT failed_attempts,locked_until FROM public.license_attempts WHERE ip_hash=$1 FOR UPDATE', [ipHash]);
      const row = q.rows[0];
      const oldUntil = row.locked_until ? new Date(row.locked_until).getTime() : 0;
      if (oldUntil > Date.now()) {
        await client.query('COMMIT');
        return { locked: true, failedAttempts: Number(row.failed_attempts) || 3, remainingAttempts: 0, lockedUntil: new Date(oldUntil).toISOString() };
      }
      const fails = oldUntil ? 1 : (Number(row.failed_attempts) || 0) + 1;
      const until = fails >= 3 ? new Date(Date.now() + 30 * 86400000) : null;
      await client.query('UPDATE public.license_attempts SET failed_attempts=$2,locked_until=$3,updated_at=NOW() WHERE ip_hash=$1', [ipHash, fails, until]);
      await client.query('COMMIT');
      return { locked: Boolean(until), failedAttempts: fails, remainingAttempts: Math.max(0, 3 - fails), lockedUntil: until ? until.toISOString() : null };
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally {
      client.release();
    }
  }

  app.get('/api/license/attempt-status', rateReady, async (req, res) => {
    try {
      res.setHeader('Cache-Control', 'no-store');
      res.json({ success: true, ...await attemptStatus(clientIp(req)) });
    } catch (e) {
      console.error('License attempt status:', e);
      res.status(500).json({ success: false, error: 'Nem sikerült lekérdezni az aktiválási állapotot.' });
    }
  });

  app.post('/api/license/activate', rateReady, async (req, res) => {
    const key = normalizeKey(req.body && req.body.licenseKey);
    const installId = String(req.body && req.body.installId || '');
    if (!/^[A-F0-9]{32}$/.test(key) || !/^[A-F0-9-]{20,80}$/i.test(installId)) {
      return res.status(400).json({ success: false, error: 'Érvénytelen kulcs vagy eszközazonosító.' });
    }
    try {
      const ip = clientIp(req);
      const status = await attemptStatus(ip);
      if (status.lockedUntil) return res.status(429).json({ success: false, error: 'Az aktiválás 30 napra letiltva.', ...status });

      const found = await pool.query('SELECT id FROM public.app_licenses WHERE key_hash=$1 AND active=TRUE LIMIT 1', [sha256(key)]);
      if (!found.rowCount) {
        const attempt = await failAttempt(ip);
        return res.status(attempt.locked ? 429 : 401).json({
          success: false,
          error: attempt.locked ? 'Három hibás próbálkozás miatt 30 napos tiltás lépett életbe.' : 'Hibás aktiválókulcs.',
          ...attempt
        });
      }

      const token = crypto.randomBytes(32).toString('hex');
      await pool.query(
        'INSERT INTO public.license_sessions (license_id,install_id,token_hash,created_at,last_seen_at) VALUES ($1,$2,$3,NOW(),NOW()) ON CONFLICT (license_id,install_id) DO UPDATE SET token_hash=EXCLUDED.token_hash,last_seen_at=NOW()',
        [found.rows[0].id, installId, sha256(token)]
      );
      await pool.query('DELETE FROM public.license_attempts WHERE ip_hash=$1', [hashIp(ip, rateSecret)]);
      res.setHeader('Cache-Control', 'no-store');
      res.json({ success: true, token });
    } catch (e) {
      console.error('License activation:', e);
      res.status(500).json({ success: false, error: 'Az aktiválás most nem sikerült.' });
    }
  });

  app.get('/api/license/status', async (req, res) => {
    const token = bearer(req);
    if (!token || token.length > 200) return res.status(401).json({ success: false, active: false });
    try {
      const q = await pool.query(
        'SELECT s.id AS session_id,l.active FROM public.license_sessions s JOIN public.app_licenses l ON l.id=s.license_id WHERE s.token_hash=$1 LIMIT 1',
        [sha256(token)]
      );
      if (!q.rowCount || !q.rows[0].active) return res.status(401).json({ success: false, active: false });
      await pool.query('UPDATE public.license_sessions SET last_seen_at=NOW() WHERE id=$1', [q.rows[0].session_id]);
      res.setHeader('Cache-Control', 'no-store');
      res.json({ success: true, active: true });
    } catch (e) {
      console.error('License status:', e);
      res.status(500).json({ success: false, active: false });
    }
  });

  app.post('/api/admin/licenses', adminOnly, async (req, res) => {
    const label = String(req.body && req.body.label || 'Licenc').trim().slice(0, 120) || 'Licenc';
    const raw = crypto.randomBytes(16).toString('hex').toUpperCase();
    const key = raw.match(/.{1,4}/g).join('-');
    try {
      const q = await pool.query(
        'INSERT INTO public.app_licenses (key_hash,label,active,created_at) VALUES ($1,$2,TRUE,NOW()) RETURNING id,label,created_at',
        [sha256(raw), label]
      );
      res.status(201).json({ success: true, license: q.rows[0], key, warning: 'A kulcsot csak most mutatjuk meg. Mentsd el.' });
    } catch (e) {
      console.error('Create license:', e);
      res.status(500).json({ success: false, error: 'Nem sikerült licencet létrehozni.' });
    }
  });

  app.get('/api/admin/licenses', adminOnly, async (req, res) => {
    try {
      const q = await pool.query(
        'SELECT l.id,l.label,l.active,l.created_at,l.revoked_at,COUNT(s.id)::int AS device_count FROM public.app_licenses l LEFT JOIN public.license_sessions s ON s.license_id=l.id GROUP BY l.id ORDER BY l.created_at DESC LIMIT 500'
      );
      res.json({ success: true, licenses: q.rows });
    } catch (e) {
      console.error('List licenses:', e);
      res.status(500).json({ success: false, error: 'Nem sikerült lekérni a licenceket.' });
    }
  });

  app.post('/api/admin/licenses/:id/revoke', adminOnly, async (req, res) => {
    if (!/^\\d+$/.test(String(req.params.id))) return res.status(400).json({ success: false, error: 'Érvénytelen licencazonosító.' });
    try {
      const q = await pool.query('UPDATE public.app_licenses SET active=FALSE,revoked_at=NOW() WHERE id=$1 AND active=TRUE RETURNING id', [req.params.id]);
      if (!q.rowCount) return res.status(404).json({ success: false, error: 'A licenc nem található vagy már visszavonták.' });
      res.json({ success: true, revoked: true });
    } catch (e) {
      console.error('Revoke license:', e);
      res.status(500).json({ success: false, error: 'Nem sikerült visszavonni a licencet.' });
    }
  });
}

async function initializeLicenseTables(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.app_licenses (
      id BIGSERIAL PRIMARY KEY,
      key_hash CHAR(64) NOT NULL UNIQUE,
      label TEXT NOT NULL DEFAULT 'Licenc',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      revoked_at TIMESTAMPTZ
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.license_sessions (
      id BIGSERIAL PRIMARY KEY,
      license_id BIGINT NOT NULL REFERENCES public.app_licenses(id) ON DELETE CASCADE,
      install_id VARCHAR(80) NOT NULL,
      token_hash CHAR(64) NOT NULL UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (license_id, install_id)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.license_attempts (
      ip_hash CHAR(64) PRIMARY KEY,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  console.log('Licencadatbázis-táblák ellenőrizve!');
}

module.exports = { registerLicenseRoutes, initializeLicenseTables };
