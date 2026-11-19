
'use strict';

const crypto = require('crypto');
const net = require('net');

const sha256 = value =>
  crypto.createHash('sha256').update(String(value)).digest('hex');

const hashIp = (ip, secret) =>
  crypto.createHmac('sha256', secret)
    .update(String(ip || 'unknown'))
    .digest('hex');

function normalizeIp(value) {
  let ip = String(value || '').trim();

  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip.includes('%')) ip = ip.split('%')[0];

  return net.isIP(ip) ? ip : 'unknown';
}

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

  return [
    iv.toString('hex'),
    cipher.getAuthTag().toString('hex'),
    encrypted.toString('hex')
  ].join(':');
}

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

  const LEGACY_TABLE = 'public.ios_license_attempts';
  const INSTALL_TABLE = 'public.ios_install_attempts';

  const clientIp = req =>
    normalizeIp(req.ip || req.socket?.remoteAddress || 'unknown');

  const validInstallId = value =>
    /^[A-F0-9-]{20,80}$/i.test(String(value || ''));

  const rateReady = (req, res, next) => {
    if (rateSecret.length < 32) {
      return res.status(503).json({
        success: false,
        error: 'A RATE_LIMIT_SECRET nincs megfelelően beállítva.'
      });
    }

    next();
  };

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

  // TELEPÍTÉSENKÉNTI PRÓBÁLKOZÁSI ÁLLAPOT
  async function attemptStatus(installId) {
    const q = await pool.query(
      `SELECT failed_attempts, locked_until
       FROM ${INSTALL_TABLE}
       WHERE install_id=$1`,
      [installId]
    );

    if (!q.rowCount) {
      return {
        failedAttempts: 0,
        remainingAttempts: 3,
        lockedUntil: null
      };
    }

    const row = q.rows[0];
    const now = Date.now();

    const until = row.locked_until
      ? new Date(row.locked_until)
      : null;

    if (until && until.getTime() > now) {
      return {
        failedAttempts: 3,
        remainingAttempts: 0,
        lockedUntil: until.toISOString()
      };
    }

    // Lejárt tiltás: az adott telepítés újra 0/3-ról indul.
    if (until && until.getTime() <= now) {
      await pool.query(
        `UPDATE ${INSTALL_TABLE}
         SET failed_attempts=0,
             locked_until=NULL,
             updated_at=NOW()
         WHERE install_id=$1`,
        [installId]
      );

      return {
        failedAttempts: 0,
        remainingAttempts: 3,
        lockedUntil: null
      };
    }

    const failedRaw = Math.max(
      0,
      Number(row.failed_attempts) || 0
    );

    if (failedRaw >= 3) {
      const repair = await pool.query(
        `UPDATE ${INSTALL_TABLE}
         SET locked_until=NOW() + INTERVAL '30 days',
             updated_at=NOW()
         WHERE install_id=$1
           AND locked_until IS NULL
           AND failed_attempts >= 3
         RETURNING locked_until`,
        [installId]
      );

      if (repair.rowCount) {
        const repairedUntil = new Date(
          repair.rows[0].locked_until
        );

        return {
          failedAttempts: 3,
          remainingAttempts: 0,
          lockedUntil: repairedUntil.toISOString()
        };
      }
    }

    const failed = Math.min(2, failedRaw);

    return {
      failedAttempts: failed,
      remainingAttempts: 3 - failed,
      lockedUntil: null
    };
  }

  // HIBÁS KULCS: KIZÁRÓLAG AZ ADOTT INSTALLID SZÁMLÁLÓJA NŐ
  async function failAttempt(installId, ip) {
    const client = await pool.connect();

    const ipHash = hashIp(ip, rateSecret);
    const encryptedIp = encryptIp(ip, rateSecret);

    try {
      await client.query('BEGIN');

      await client.query(
        `INSERT INTO ${INSTALL_TABLE}
         (install_id, ip_hash, failed_attempts,
          updated_at, ip_encrypted)
         VALUES ($1, $2, 0, NOW(), $3)
         ON CONFLICT (install_id) DO NOTHING`,
        [installId, ipHash, encryptedIp]
      );

      const q = await client.query(
        `SELECT failed_attempts, locked_until
         FROM ${INSTALL_TABLE}
         WHERE install_id=$1
         FOR UPDATE`,
        [installId]
      );

      const row = q.rows[0];

      const oldUntil = row.locked_until
        ? new Date(row.locked_until).getTime()
        : 0;

      if (oldUntil > Date.now()) {
        await client.query('COMMIT');

        return {
          locked: true,
          failedAttempts: 3,
          remainingAttempts: 0,
          lockedUntil: new Date(oldUntil).toISOString()
        };
      }

      const oldFailed = oldUntil
        ? 0
        : Math.min(
            2,
            Math.max(0, Number(row.failed_attempts) || 0)
          );

      const fails = oldFailed + 1;

      const until = fails >= 3
        ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
        : null;

      await client.query(
        `UPDATE ${INSTALL_TABLE}
         SET failed_attempts=$2,
             locked_until=$3,
             ip_hash=$4,
             ip_encrypted=$5,
             updated_at=NOW()
         WHERE install_id=$1`,
        [installId, fails, until, ipHash, encryptedIp]
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

  // ADMIN OLDAL
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
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;display:grid;place-items:center;
  padding:20px;background:#0b0f19;color:white;
  font-family:Arial,sans-serif
}
.panel{
  width:100%;max-width:650px;padding:25px;
  border:1px solid #374151;border-radius:18px;
  background:#151c2b
}
h2{color:#fbbf24;margin-top:0}
p{color:#cbd5e1}
label{display:block;margin-top:12px}
input{
  width:100%;padding:14px;margin:8px 0 15px;
  border:1px solid #475569;border-radius:9px;
  background:#0b0f19;color:white;font-size:16px
}
button{
  width:100%;padding:14px;border:0;border-radius:9px;
  background:#dc2626;color:white;font-weight:bold;
  font-size:15px;cursor:pointer;margin-top:8px
}
button:disabled{opacity:.6}
.secondary{background:#334155}
#result{
  margin-top:15px;padding:12px;border-radius:8px;
  display:none;overflow-wrap:anywhere
}
.ban{
  border:1px solid #475569;border-radius:10px;
  padding:13px;margin-top:10px;background:#0b0f19;
  overflow-wrap:anywhere
}
.small{color:#94a3b8;font-size:13px;line-height:1.5}
hr{border:0;border-top:1px solid #374151;margin:22px 0}
</style>
</head>
<body>
<div class="panel">
<h2>🔐 iOS Admin</h2>
<p>Telepítésenkénti próbálkozások és régi IP-rekordok kezelése</p>

<label>Admin API kulcs</label>
<input id="adminKey" type="password"
placeholder="Admin kulcs" autocomplete="off">

<button class="secondary" onclick="loadBans()">
📋 Összes rekord betöltése
</button>

<div id="result"></div>
<div id="banList"></div>

<hr>

<h3>➕ Kézi feloldás IP alapján</h3>
<label>IP-cím</label>
<input id="ip" type="text"
placeholder="Például: 192.168.1.100" autocomplete="off">

<button onclick="manualUnban()">🔓 IP tiltás feloldása</button>

<button class="secondary" onclick="unbanCurrentIp()">
🔓 Saját aktuális IP-címem feloldása
</button>

<p class="small">
Az új rendszer telepítésenként számolja a próbálkozásokat.
Az IP-alapú régi rekordok is megmaradnak a listában.
</p>
</div>

<script>
function getKey(){
  return document.getElementById('adminKey').value.trim();
}

function showResult(message,success){
  const el=document.getElementById('result');
  el.style.display='block';
  el.textContent=message;
  el.style.background=success?'#14532d':'#7f1d1d';
}

async function api(url,options={}){
  return fetch(url,{
    cache:'no-store',
    ...options,
    headers:{
      'Authorization':'Bearer '+getKey(),
      ...options.headers
    }
  });
}

async function loadBans(){
  if(!getKey()){
    showResult('Először add meg az admin API kulcsot!',false);
    return;
  }

  const list=document.getElementById('banList');
  list.textContent='Rekordok betöltése...';

  try{
    const response=await api('/api/admin/ios-bans');
    const data=await response.json();

    if(!response.ok||!data.success){
      list.textContent='';
      showResult(data.error||'Nem sikerült betölteni a listát.',false);
      return;
    }

    list.textContent='';

    if(!data.bans || !data.bans.length){
      list.textContent='Jelenleg nincs tárolt rekord.';
      showResult('A lista sikeresen betöltve.',true);
      return;
    }

    data.bans.forEach(ban=>{
      const card=document.createElement('div');
      card.className='ban';

      const ip=document.createElement('strong');
      ip.textContent='IP: '+(ban.ip||'nem visszafejthető');

      const type=document.createElement('div');
      type.textContent='Rekord típusa: '+
        (ban.installId?'Telepítésenkénti':'Régi IP-alapú');

      card.append(ip,type);

      if(ban.installId){
        const install=document.createElement('div');
        install.textContent='Telepítésazonosító: '+ban.installId;
        card.appendChild(install);
      }

      const tag=document.createElement('div');
      tag.textContent='IP-azonosító: '+ban.ipTag;

      const attempts=document.createElement('div');
      attempts.textContent='Hibás próbálkozások: '+ban.failedAttempts+'/3';

      const status=document.createElement('div');
      status.textContent='Állapot: '+ban.status;

      const updated=document.createElement('div');
      updated.textContent='Utolsó aktivitás: '+
        (ban.updatedAt
          ? new Date(ban.updatedAt).toLocaleString('hu-HU')
          : 'Ismeretlen');

      card.append(tag,attempts,status,updated);

      if(ban.lockedUntil){
        const until=document.createElement('div');
        until.textContent='Tiltás lejárata: '+
          new Date(ban.lockedUntil).toLocaleString('hu-HU');
        card.appendChild(until);
      }

      if(ban.status==='Aktív tiltás'){
        const button=document.createElement('button');

        button.textContent='🔓 Tiltás feloldása';

        if(ban.installId){
          button.onclick=()=>unbanInstall(ban.installId);
        }else{
          button.onclick=()=>unbanTag(ban.ipTag);
        }

        card.appendChild(button);
      }

      list.appendChild(card);
    });

    showResult(
      'Betöltve: '+data.bans.length+' rekord.',
      true
    );

  }catch(error){
    list.textContent='';
    showResult('Kapcsolódási hiba a szerverrel.',false);
  }
}

async function unbanInstall(installId){
  if(!confirm('Biztosan feloldod ennek a telepítésnek a tiltását?')) return;

  try{
    const response=await api('/api/admin/ios-unban-install',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({installId})
    });

    const data=await response.json();

    showResult(data.message||data.error||'Szerverválasz érkezett.',
      data.success&&data.unbanned);

    if(data.success&&data.unbanned) await loadBans();
  }catch(error){
    showResult('Nem sikerült kapcsolódni a szerverhez.',false);
  }
}

async function unbanTag(ipTag){
  if(!confirm('Biztosan feloldod az ehhez az IP-azonosítóhoz tartozó rekordokat?')) return;

  try{
    const response=await api('/api/admin/ios-unban-tag',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ipTag})
    });

    const data=await response.json();

    showResult(data.message||data.error||'Szerverválasz érkezett.',
      data.success&&data.unbanned);

    if(data.success&&data.unbanned) await loadBans();
  }catch(error){
    showResult('Nem sikerült kapcsolódni a szerverhez.',false);
  }
}

async function unbanIp(ip){
  if(!confirm('Biztosan feloldod az ehhez az IP-címhez tartozó rekordokat: '+ip+'?')) return;

  try{
    const response=await api('/api/admin/ios-unban',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ip})
    });

    const data=await response.json();

    showResult(data.message||data.error||'Szerverválasz érkezett.',
      data.success&&data.unbanned);

    if(data.success&&data.unbanned) await loadBans();
  }catch(error){
    showResult('Nem sikerült kapcsolódni a szerverhez.',false);
  }
}

async function unbanCurrentIp(){
  if(!getKey()){
    showResult('Először add meg az admin API kulcsot!',false);
    return;
  }

  if(!confirm('Biztosan feloldod a szerver által érzékelt IP-címhez tartozó rekordokat?')) return;

  try{
    const response=await api('/api/admin/ios-unban-current',{method:'POST'});
    const data=await response.json();

    showResult(data.message||data.error||'Szerverválasz érkezett.',
      data.success&&data.unbanned);

    if(data.success&&data.unbanned) await loadBans();
  }catch(error){
    showResult('Nem sikerült kapcsolódni a szerverhez.',false);
  }
}

async function manualUnban(){
  const ip=document.getElementById('ip').value.trim();

  if(!ip){
    showResult('Írd be a feloldandó IP-címet!',false);
    return;
  }

  await unbanIp(ip);
  document.getElementById('ip').value='';
}
</script>
</body>
</html>`);
  });

  // ADMIN: ÚJ TELEPÍTÉSI ÉS RÉGI IP-REKORDOK LISTÁJA
  app.get('/api/admin/ios-bans', rateReady, async (req, res) => {
    if (!checkAdmin(req, res)) return;

    try {
      const [installResult, legacyResult] = await Promise.all([
        pool.query(
          `SELECT install_id, ip_hash, ip_encrypted,
                  failed_attempts, locked_until, updated_at
           FROM ${INSTALL_TABLE}
           ORDER BY updated_at DESC`
        ),
        pool.query(
          `SELECT ip_hash, ip_encrypted,
                  failed_attempts, locked_until, updated_at
           FROM ${LEGACY_TABLE}
           ORDER BY updated_at DESC`
        )
      ]);

      const now = Date.now();

      function makeStatus(row) {
        const until = row.locked_until
          ? new Date(row.locked_until)
          : null;

        if (until && until.getTime() > now) return 'Aktív tiltás';
        if (until && until.getTime() <= now) return 'Lejárt tiltás';

        const fails = Number(row.failed_attempts) || 0;

        return fails > 0
          ? 'Folyamatban lévő próbálkozás'
          : 'Nincs aktív tiltás';
      }

      const installBans = installResult.rows.map(row => ({
        installId: row.install_id,
        ip: decryptIp(row.ip_encrypted, rateSecret),
        ipTag: String(row.ip_hash).slice(0, 12),
        failedAttempts: Number(row.failed_attempts) || 0,
        status: makeStatus(row),
        lockedUntil: row.locked_until
          ? new Date(row.locked_until).toISOString()
          : null,
        updatedAt: row.updated_at
          ? new Date(row.updated_at).toISOString()
          : null
      }));

      const legacyBans = legacyResult.rows.map(row => ({
        installId: null,
        ip: decryptIp(row.ip_encrypted, rateSecret),
        ipTag: String(row.ip_hash).slice(0, 12),
        failedAttempts: Number(row.failed_attempts) || 0,
        status: makeStatus(row),
        lockedUntil: row.locked_until
          ? new Date(row.locked_until).toISOString()
          : null,
        updatedAt: row.updated_at
          ? new Date(row.updated_at).toISOString()
          : null
      }));

      const bans = [...installBans, ...legacyBans]
        .sort((a, b) =>
          new Date(b.updatedAt || 0) - new Date(a.updatedAt || 0)
        );

      res.setHeader('Cache-Control', 'no-store');

      return res.json({
        success: true,
        total: bans.length,
        bans
      });

    } catch (error) {
      console.error('iOS admin attempts list:', error);

      return res.status(500).json({
        success: false,
        error: 'A próbálkozási lista betöltése nem sikerült.'
      });
    }
  });

  // ADMIN: EGY KONKRÉT TELEPÍTÉS FELOLDÁSA
  app.post('/api/admin/ios-unban-install', rateReady, async (req, res) => {
    if (!checkAdmin(req, res)) return;

    const installId = String(req.body?.installId || '');

    if (!validInstallId(installId)) {
      return res.status(400).json({
        success: false,
        error: 'Érvénytelen telepítésazonosító.'
      });
    }

    try {
      const result = await pool.query(
        `DELETE FROM ${INSTALL_TABLE}
         WHERE install_id=$1`,
        [installId]
      );

      res.setHeader('Cache-Control', 'no-store');

      return res.json({
        success: true,
        unbanned: result.rowCount > 0,
        message: result.rowCount > 0
          ? 'A telepítés tiltása sikeresen feloldva.'
          : 'Ehhez a telepítéshez nem található rekord.'
      });

    } catch (error) {
      console.error('iOS unban install:', error);

      return res.status(500).json({
        success: false,
        error: 'A telepítés feloldása nem sikerült.'
      });
    }
  });

  // ADMIN: RÉGI IP-AZONOSÍTÓ ALAPJÁN FELOLDÁS
  app.post('/api/admin/ios-unban-tag', rateReady, async (req, res) => {
    if (!checkAdmin(req, res)) return;

    const ipTag = String(req.body?.ipTag || '').trim().toLowerCase();

    if (!/^[a-f0-9]{12}$/.test(ipTag)) {
      return res.status(400).json({
        success: false,
        error: 'Érvénytelen IP-azonosító.'
      });
    }

    try {
      const [legacy, installs] = await Promise.all([
        pool.query(
          `DELETE FROM ${LEGACY_TABLE}
           WHERE LEFT(ip_hash, 12)=$1`,
          [ipTag]
        ),
        pool.query(
          `DELETE FROM ${INSTALL_TABLE}
           WHERE LEFT(ip_hash, 12)=$1`,
          [ipTag]
        )
      ]);

      const count = legacy.rowCount + installs.rowCount;

      res.setHeader('Cache-Control', 'no-store');

      return res.json({
        success: true,
        unbanned: count > 0,
        message: count > 0
          ? 'Az ehhez az IP-azonosítóhoz tartozó rekordok feloldva.'
          : 'Ehhez az IP-azonosítóhoz nem található rekord.'
      });

    } catch (error) {
      console.error('iOS admin unban by tag:', error);

      return res.status(500).json({
        success: false,
        error: 'A tiltás feloldása nem sikerült.'
      });
    }
  });

  // ADMIN: KÉZI IP-FELOLDÁS
  app.post('/api/admin/ios-unban', rateReady, async (req, res) => {
    if (!checkAdmin(req, res)) return;

    const ip = normalizeIp(req.body?.ip);

    if (ip === 'unknown') {
      return res.status(400).json({
        success: false,
        error: 'Érvénytelen IP-cím.'
      });
    }

    const ipHash = hashIp(ip, rateSecret);

    try {
      const [legacy, installs] = await Promise.all([
        pool.query(
          `DELETE FROM ${LEGACY_TABLE} WHERE ip_hash=$1`,
          [ipHash]
        ),
        pool.query(
          `DELETE FROM ${INSTALL_TABLE} WHERE ip_hash=$1`,
          [ipHash]
        )
      ]);

      const count = legacy.rowCount + installs.rowCount;

      res.setHeader('Cache-Control', 'no-store');

      return res.json({
        success: true,
        unbanned: count > 0,
        message: count > 0
          ? 'Az IP-címhez tartozó rekordok feloldva.'
          : 'Ehhez az IP-címhez nem található rekord.'
      });

    } catch (error) {
      console.error('iOS admin unban:', error);

      return res.status(500).json({
        success: false,
        error: 'A tiltás feloldása nem sikerült.'
      });
    }
  });

  // ADMIN: AZ ADMINOLDAL ÁLTAL HASZNÁLT IP FELOLDÁSA
  app.post('/api/admin/ios-unban-current', rateReady, async (req, res) => {
    if (!checkAdmin(req, res)) return;

    try {
      const ip = clientIp(req);

      if (ip === 'unknown') {
        return res.status(400).json({
          success: false,
          error: 'A szerver nem tudott érvényes IP-címet azonosítani.'
        });
      }

      const ipHash = hashIp(ip, rateSecret);

      const [legacy, installs] = await Promise.all([
        pool.query(
          `DELETE FROM ${LEGACY_TABLE} WHERE ip_hash=$1`,
          [ipHash]
        ),
        pool.query(
          `DELETE FROM ${INSTALL_TABLE} WHERE ip_hash=$1`,
          [ipHash]
        )
      ]);

      const count = legacy.rowCount + installs.rowCount;

      res.setHeader('Cache-Control', 'no-store');

      return res.json({
        success: true,
        unbanned: count > 0,
        message: count > 0
          ? 'A jelenlegi IP-címhez tartozó rekordok feloldva.'
          : 'Ehhez az IP-címhez nem található rekord.'
      });

    } catch (error) {
      console.error('iOS current IP unban:', error);

      return res.status(500).json({
        success: false,
        error: 'A feloldás nem sikerült.'
      });
    }
  });

  // PRÓBÁLKOZÁSI ÁLLAPOT LEKÉRDEZÉSE INSTALLID ALAPJÁN
  app.get('/api/ios/attempt-status', rateReady, async (req, res) => {
    try {
      const installId = String(req.query.installId || '');

      if (!validInstallId(installId)) {
        return res.status(400).json({
          success: false,
          error: 'Érvénytelen vagy hiányzó telepítésazonosító.'
        });
      }

      res.setHeader('Cache-Control', 'no-store');

      return res.json({
        success: true,
        ...await attemptStatus(installId)
      });

    } catch (error) {
      console.error('iOS attempt status:', error);

      return res.status(500).json({
        success: false,
        error: 'Nem sikerült lekérdezni a próbálkozási állapotot.'
      });
    }
  });

  // iOS AKTIVÁLÁS
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
      !validInstallId(installId)
    ) {
      return res.status(400).json({
        success: false,
        error: 'Érvénytelen kulcs vagy eszközazonosító.'
      });
    }

    try {
      const ip = clientIp(req);

      if (ip === 'unknown') {
        return res.status(400).json({
          success: false,
          error: 'A szerver nem tudta azonosítani az IP-címet.'
        });
      }

      const status = await attemptStatus(installId);

      if (status.lockedUntil) {
        return res.status(429).json({
          success: false,
          error: 'Három hibás próbálkozás miatt 30 napos tiltás van érvényben.',
          ...status
        });
      }

      if (!safeEqual(submittedKey, serverKey)) {
        const attempt = await failAttempt(installId, ip);

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

      // Sikeres aktiváláskor a számláló nullázódik,
      // de a rekord megmarad az adminlistában.
      await pool.query(
        `UPDATE ${INSTALL_TABLE}
         SET failed_attempts=0,
             locked_until=NULL,
             ip_hash=$2,
             ip_encrypted=$3,
             updated_at=NOW()
         WHERE install_id=$1`,
        [
          installId,
          hashIp(ip, rateSecret),
          encryptIp(ip, rateSecret)
        ]
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

  // AKTIVÁLÁSI ÁLLAPOT ELLENŐRZÉSE
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
        `UPDATE public.ios_activation_sessions
         SET last_seen_at=NOW()
         WHERE id=$1`,
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
  // Az iOS aktivált eszközei.
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

  // Régi közös tábla titkosított IP-oszlopa.
  await pool.query(`
    ALTER TABLE public.license_attempts
    ADD COLUMN IF NOT EXISTS ip_encrypted TEXT
  `);

  // Régi IP-alapú iOS-rekordok táblája.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.ios_license_attempts (
      ip_hash CHAR(64) PRIMARY KEY,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ip_encrypted TEXT
    )
  `);

  // A régi iOS-adatok átvitele, felülírás nélkül.
  await pool.query(`
    INSERT INTO public.ios_license_attempts
      (ip_hash, failed_attempts, locked_until, updated_at, ip_encrypted)
    SELECT
      ip_hash,
      failed_attempts,
      locked_until,
      COALESCE(updated_at, NOW()),
      ip_encrypted
    FROM public.license_attempts
    WHERE ip_encrypted IS NOT NULL
    ON CONFLICT (ip_hash)
    DO NOTHING
  `);

  // ÚJ: telepítésenkénti próbálkozási tábla.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.ios_install_attempts (
      install_id VARCHAR(80) PRIMARY KEY,
      ip_hash CHAR(64) NOT NULL,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ip_encrypted TEXT
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS ios_install_attempts_ip_hash_idx
    ON public.ios_install_attempts (ip_hash)
  `);

  console.log(
    'iOS aktiválási rendszer ellenőrizve: telepítésenkénti próbálkozásszámlálás aktív.'
  );
}

module.exports = {
  registerIosActivationRoutes,
  initializeIosActivationTables
};
