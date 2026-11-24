// ============================================================
// İş Radar - Şifre yenileme (Express + Mongoose)
//
// KURULUM (arkadaşın için):
//
// 1) Bu dosyayı backend projesine "password_reset.js" adıyla koy.
//
// 2) server.js (ya da app.js) içinde, app oluşturulduktan ve
//    app.use(express.json()) satırından SONRA şunu ekle:
//
//      const bcrypt = require('bcryptjs');   // projede hangisi kullanılıyorsa (bcrypt / bcryptjs)
//      const User = require('./models/User'); // kullanıcı modelinin gerçek yolu
//      require('./password_reset')(app, {
//        User,
//        hashPassword: (plain) => bcrypt.hash(plain, 10),
//      });
//
//    Kayıtta şifre farklı bir yöntemle hash'leniyorsa hashPassword'ü ona göre değiştir.
//    Kullanıcı e-postası modelde "email" alanında tutulmalı.
//
// 3) Render > Environment bölümüne şu değişkenleri ekle:
//      BREVO_API_KEY = (Brevo hesabından alınan API anahtarı)
//      MAIL_FROM     = (Brevo'da doğruladığın gönderen e-posta adresi)
//      MAIL_FROM_NAME= İş Radar
//      PUBLIC_URL    = https://is-radar-api.onrender.com
//
// NEDEN BREVO? Render'ın ücretsiz planı SMTP portlarını (25, 465, 587) engelliyor,
// bu yüzden Gmail/nodemailer ile mail gitmez. Brevo HTTP API'si ile gönderilir.
// Brevo ücretsiz planı günde 300 mail verir. brevo.com'da hesap aç,
// "Senders" bölümünde gönderen e-posta adresini doğrula, "SMTP & API" bölümünden
// API anahtarı oluştur. (Node 18+ gerekir, fetch dahili gelir.)
// ============================================================

const crypto = require('crypto');
const mongoose = require('mongoose');

// Sıfırlama kayıtları ayrı koleksiyonda tutulur, süresi dolunca MongoDB otomatik siler.
const resetSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  tokenHash: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } },
});
const PasswordReset = mongoose.models.PasswordReset || mongoose.model('PasswordReset', resetSchema);

const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');
const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const escapeHtml = (text) =>
  String(text).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const TOKEN_LIFETIME_MS = 60 * 60 * 1000; // 1 saat
const MIN_PASSWORD_LENGTH = 6;

async function sendResetMail(to, name, link) {
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': process.env.BREVO_API_KEY,
      'content-type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify({
      sender: { name: process.env.MAIL_FROM_NAME || 'İş Radar', email: process.env.MAIL_FROM },
      to: [{ email: to }],
      subject: 'İş Radar - Şifre yenileme bağlantın',
      htmlContent: `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;color:#222">
          <h2 style="color:#1A237E">İş Radar</h2>
          <p>Merhaba ${escapeHtml(name || '')},</p>
          <p>Şifreni yenilemek için aşağıdaki düğmeye tıkla. Bağlantı <b>1 saat</b> geçerlidir.</p>
          <p style="margin:28px 0">
            <a href="${link}" style="background:#1A237E;color:#fff;padding:12px 22px;border-radius:10px;text-decoration:none;font-weight:bold">Şifremi Yenile</a>
          </p>
          <p style="font-size:13px;color:#666">Düğme çalışmazsa bu adresi tarayıcına yapıştır:<br>${link}</p>
          <p style="font-size:13px;color:#666">Bu isteği sen yapmadıysan bu e-postayı yok sayabilirsin, şifren değişmez.</p>
        </div>`,
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Brevo hatası ${res.status}: ${body}`);
  }
}

function resetPage(token, message) {
  const safeToken = escapeHtml(token || '');
  return `<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>İş Radar - Şifre Yenile</title>
<style>
  body{font-family:Arial,sans-serif;background:#F7F8FA;margin:0;padding:24px;color:#222}
  .card{max-width:420px;margin:40px auto;background:#fff;border-radius:20px;padding:28px;border:1px solid #e5e7eb}
  h2{color:#1A237E;margin-top:0}
  input{width:100%;box-sizing:border-box;padding:13px;margin:6px 0 14px;border:1px solid #ccc;border-radius:12px;font-size:15px}
  button{width:100%;padding:14px;background:#1A237E;color:#fff;border:0;border-radius:12px;font-size:16px;font-weight:bold;cursor:pointer}
  button:disabled{opacity:.6}
  #msg{margin-top:14px;font-size:14px}
  .err{color:#d32f2f}.ok{color:#2e7d32}
</style></head>
<body><div class="card">
  <h2>Yeni Şifre Belirle</h2>
  ${message ? `<p class="err">${escapeHtml(message)}</p>` : `
  <form id="f">
    <label>Yeni şifre</label>
    <input type="password" id="p1" minlength="${MIN_PASSWORD_LENGTH}" required placeholder="En az ${MIN_PASSWORD_LENGTH} karakter">
    <label>Yeni şifre (tekrar)</label>
    <input type="password" id="p2" minlength="${MIN_PASSWORD_LENGTH}" required>
    <button id="b" type="submit">Şifremi Kaydet</button>
    <div id="msg"></div>
  </form>
  <script>
    document.getElementById('f').addEventListener('submit', async (e) => {
      e.preventDefault();
      const msg = document.getElementById('msg');
      const p1 = document.getElementById('p1').value;
      const p2 = document.getElementById('p2').value;
      if (p1 !== p2) { msg.className = 'err'; msg.textContent = 'Şifreler aynı değil.'; return; }
      const b = document.getElementById('b'); b.disabled = true;
      try {
        const r = await fetch('/api/reset-password', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: '${safeToken}', password: p1 })
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok) { msg.className = 'ok'; msg.textContent = 'Şifren güncellendi. Uygulamaya dönüp yeni şifrenle giriş yapabilirsin.'; document.getElementById('f').querySelectorAll('input,label').forEach(x => x.style.display='none'); b.style.display='none'; }
        else { msg.className = 'err'; msg.textContent = d.error || 'Bir hata oluştu.'; b.disabled = false; }
      } catch (err) { msg.className = 'err'; msg.textContent = 'Sunucuya ulaşılamadı.'; b.disabled = false; }
    });
  </script>`}
</div></body></html>`;
}

module.exports = function registerPasswordReset(app, { User, hashPassword }) {
  // 1) Uygulama e-posta adresini gönderir, kullanıcıya bağlantı mailı gider.
  app.post('/api/forgot-password', async (req, res) => {
    // Her durumda aynı cevap verilir, böylece e-postanın kayıtlı olup olmadığı açığa çıkmaz.
    const genericOk = { message: 'Bu e-posta kayıtlıysa şifre yenileme bağlantısı gönderildi.' };
    try {
      const email = String(req.body?.email || '').trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Geçerli bir e-posta girin.' });
      }

      const user = await User.findOne({ email: new RegExp('^' + escapeRegex(email) + '$', 'i') });
      if (!user) return res.status(200).json(genericOk);

      // Aynı kullanıcının eski bağlantıları geçersiz olur.
      await PasswordReset.deleteMany({ userId: user._id });

      const token = crypto.randomBytes(32).toString('hex');
      await PasswordReset.create({
        userId: user._id,
        tokenHash: sha256(token),
        expiresAt: new Date(Date.now() + TOKEN_LIFETIME_MS),
      });

      const base = (process.env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
      const link = `${base}/reset-password?token=${token}`;
      await sendResetMail(user.email, user.full_name || user.name, link);

      return res.status(200).json(genericOk);
    } catch (err) {
      console.error('forgot-password hatası:', err);
      return res.status(500).json({ error: 'Mail gönderilemedi, biraz sonra tekrar dene.' });
    }
  });

  // 2) Mailden gelen bağlantı: yeni şifre formu.
  app.get('/reset-password', async (req, res) => {
    const token = String(req.query.token || '');
    const record = token ? await PasswordReset.findOne({ tokenHash: sha256(token), expiresAt: { $gt: new Date() } }) : null;
    res.set('Cache-Control', 'no-store');
    if (!record) {
      return res.status(400).send(resetPage('', 'Bu bağlantı geçersiz ya da süresi dolmuş. Uygulamadan yeni bir bağlantı iste.'));
    }
    return res.send(resetPage(token, ''));
  });

  // 3) Form yeni şifreyi gönderir, şifre veritabanında güncellenir (kalıcı).
  app.post('/api/reset-password', async (req, res) => {
    try {
      const token = String(req.body?.token || '');
      const password = String(req.body?.password || '');
      if (password.length < MIN_PASSWORD_LENGTH) {
        return res.status(400).json({ error: `Şifre en az ${MIN_PASSWORD_LENGTH} karakter olmalı.` });
      }

      const record = await PasswordReset.findOne({ tokenHash: sha256(token), expiresAt: { $gt: new Date() } });
      if (!record) {
        return res.status(400).json({ error: 'Bağlantı geçersiz ya da süresi dolmuş. Yeni bir bağlantı iste.' });
      }

      const user = await User.findById(record.userId);
      if (!user) return res.status(400).json({ error: 'Kullanıcı bulunamadı.' });

      // Kayıt/giriş şifreyi hangi alanda tutuyorsa orası güncellenir (password / password_hash).
      const hashed = await hashPassword(password);
      const field = user.password_hash !== undefined && user.password === undefined ? 'password_hash' : 'password';
      user[field] = hashed;
      await user.save();

      await PasswordReset.deleteMany({ userId: user._id }); // bağlantı tek kullanımlık
      return res.status(200).json({ message: 'Şifren güncellendi.' });
    } catch (err) {
      console.error('reset-password hatası:', err);
      return res.status(500).json({ error: 'Şifre güncellenemedi, tekrar dene.' });
    }
  });
};
