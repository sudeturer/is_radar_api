const crypto = require('node:crypto');
const dns = require('node:dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ---------------------------------------------------------------------------
// Ayarlar (Render > Environment bölümünden gelir, koda yazılmaz)
//   MONGO_URI  : MongoDB bağlantı adresi
//   JWT_SECRET : token'ları imzalamak için uzun rastgele bir yazı
// ---------------------------------------------------------------------------
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error(">>> HATA: MONGO_URI tanımlı değil! Render > Environment bölümüne ekleyin.");
}

let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  // Tanımlı değilse geçici bir anahtar üretir; sunucu her yeniden başladığında
  // herkes çıkış yapmış olur. Render'a JWT_SECRET eklenince kalıcı olur.
  JWT_SECRET = crypto.randomBytes(32).toString('hex');
  console.warn(">>> UYARI: JWT_SECRET tanımlı değil, geçici anahtar kullanılıyor.");
}

mongoose.connect(MONGO_URI)
  .then(() => console.log(">>> MongoDB Atlas veritabanına başarıyla bağlanıldı!"))
  .catch(err => console.error(">>> Bağlantı hatası:", err.message));

// ---------------------------------------------------------------------------
// Token (JWT, HS256) — ek paket gerekmez, Node'un kendi crypto modülü yeter
// ---------------------------------------------------------------------------
const b64url = (input) => Buffer.from(input).toString('base64url');

function signToken(payload, expiresInSec = 7 * 24 * 3600) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify({
    ...payload,
    exp: Math.floor(Date.now() / 1000) + expiresInSec
  }));
  const sig = crypto.createHmac('sha256', JWT_SECRET)
    .update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  const [h, b, s] = parts;
  const expected = crypto.createHmac('sha256', JWT_SECRET)
    .update(`${h}.${b}`).digest('base64url');
  const a = Buffer.from(s);
  const e = Buffer.from(expected);
  if (a.length !== e.length || !crypto.timingSafeEqual(a, e)) return null;
  try {
    const payload = JSON.parse(Buffer.from(b, 'base64url').toString());
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

// Korumalı adreslerin başına konur: geçerli token yoksa 401 döner,
// varsa giriş yapan kullanıcının id'sini req.userId'ye yazar.
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = verifyToken(token);
  if (!payload || !payload.id) {
    return res.status(401).json({ error: "Oturum geçersiz, lütfen tekrar giriş yapın." });
  }
  req.userId = payload.id;
  next();
}

// ---------------------------------------------------------------------------
// Koleksiyon Modelleri
// ---------------------------------------------------------------------------
const InternshipPost = mongoose.model('internship_posts', new mongoose.Schema({
  // eski alanlar (öğrenci ekranı bunları okuyor, kalsın)
  company_name: String,
  city: String,
  department: String,
  positions: [String],
  description: String,
  contact_email: String,
  // firma ilan formu alanları
  owner_id: String,
  position: String,
  work_type: String,
  requirements: String,
  duration: String,
  created_at: { type: Date, default: Date.now }
}));

const User = mongoose.model('users', new mongoose.Schema({
  full_name: String,
  email: String,
  password: String,
  phone: String,
  role: String,
  education_info: Object,
  preferences: Object,
  profile: Object,
  created_at: { type: Date, default: Date.now }
}));

const Application = mongoose.model('applications', new mongoose.Schema({
  post_id: String,
  post_position: String,
  company_id: String,
  company_name: String,
  student_id: String,
  student_name: String,
  student_email: String,
  note: String,
  status: { type: String, default: 'Beklemede' },
  created_at: { type: Date, default: Date.now }
}));

const Message = mongoose.model('messages', new mongoose.Schema({
  from_id: String,
  to_id: String,
  text: String,
  created_at: { type: Date, default: Date.now }
}));

const isId = (v) => mongoose.isValidObjectId(v);
const ROLES = ['student', 'graduate', 'coach', 'company'];

// Şifre alanı olmadan kullanıcıyı döndürür
function safeUser(user) {
  const obj = user.toObject ? user.toObject() : { ...user };
  delete obj.password;
  return obj;
}

// ---------------------------------------------------------------------------
// HERKESE AÇIK adresler
// ---------------------------------------------------------------------------
app.get('/api/internships', async (req, res) => {
  try {
    const posts = await InternshipPost.find();
    res.json(posts);
  } catch (error) {
    console.error("İlan çekme hatası detayı:", error);
    res.status(500).json({ error: error.message });
  }
});

// Şifre alanı artık dönmüyor
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    console.error("Kullanıcı çekme hatası detayı:", error);
    res.status(500).json({ error: error.message });
  }
});

// Kayıt: cevapta kullanıcı (şifresiz) + token döner
app.post('/api/register', async (req, res) => {
  try {
    const { full_name, email, password, role } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "E-posta ve şifre zorunludur." });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(409).json({ error: "Bu e-posta ile zaten bir hesap var." });
    }

    const newUser = await User.create({
      full_name,
      email,
      password,
      role: ROLES.includes(role) ? role : 'student'
    });

    const token = signToken({ id: newUser._id.toString(), role: newUser.role });
    res.status(201).json({ message: "Kayıt başarılı!", user: safeUser(newUser), token });
  } catch (error) {
    console.error("Kayıt hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// Giriş: cevapta kullanıcı (şifresiz) + token döner
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).json({ error: "E-posta veya şifre hatalı." });
    }

    const token = signToken({ id: user._id.toString(), role: user.role });
    res.json({ message: "Giriş başarılı!", user: safeUser(user), token });
  } catch (error) {
    console.error("Giriş hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// TOKEN GEREKTİREN adresler (kullanıcı kimliği token'dan alınır)
// ---------------------------------------------------------------------------

// ---- Profil (her hesap türü kendi profilini okur/yazar) ----
app.get('/api/profile', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('profile');
    if (!user) return res.status(404).json({ error: "Kullanıcı bulunamadı." });
    res.json(user.profile || {});
  } catch (error) {
    console.error("Profil okuma hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/profile', auth, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.userId,
      { profile: req.body },
      { new: true }
    ).select('profile');
    if (!user) return res.status(404).json({ error: "Kullanıcı bulunamadı." });
    res.json(user.profile || {});
  } catch (error) {
    console.error("Profil kaydetme hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// ---- Firma: ilan aç / kendi ilanlarını gör ----
app.post('/api/posts', auth, async (req, res) => {
  try {
    const { position, city, work_type, requirements, duration, description } = req.body;

    if (!position || !city) {
      return res.status(400).json({ error: "Pozisyon ve şehir zorunludur." });
    }

    const me = await User.findById(req.userId);
    if (!me || me.role !== 'company') {
      return res.status(403).json({ error: "Sadece firma hesapları ilan açabilir." });
    }

    const post = await InternshipPost.create({
      owner_id: req.userId,
      company_name: me.full_name,
      contact_email: me.email,
      position, city, work_type, requirements, duration, description,
      department: position,
      positions: [position]
    });

    res.status(201).json(post);
  } catch (error) {
    console.error("İlan açma hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/posts/mine', auth, async (req, res) => {
  try {
    const posts = await InternshipPost.find({ owner_id: req.userId }).sort({ created_at: -1 });
    res.json(posts);
  } catch (error) {
    console.error("Firma ilanları hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// Firma kendi ilanını siler
app.delete('/api/posts/:id', auth, async (req, res) => {
  try {
    if (!isId(req.params.id)) return res.status(400).json({ error: "Geçersiz ilan." });
    const r = await InternshipPost.deleteOne({ _id: req.params.id, owner_id: req.userId });
    if (!r.deletedCount) return res.status(404).json({ error: "İlan bulunamadı." });
    res.json({ ok: true });
  } catch (error) {
    console.error("İlan silme hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// Firma başvuru durumunu günceller (Beklemede / Kabul Edildi / Reddedildi)
app.patch('/api/applications/:id', auth, async (req, res) => {
  try {
    const { status } = req.body;
    if (!isId(req.params.id)) return res.status(400).json({ error: "Geçersiz başvuru." });
    if (!['Beklemede', 'Kabul Edildi', 'Reddedildi'].includes(status)) {
      return res.status(400).json({ error: "Geçersiz durum." });
    }
    const app_ = await Application.findOneAndUpdate(
      { _id: req.params.id, company_id: req.userId },
      { status },
      { new: true }
    );
    if (!app_) return res.status(404).json({ error: "Başvuru bulunamadı." });
    res.json(app_);
  } catch (error) {
    console.error("Başvuru güncelleme hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// ---- Başvurular ----
app.post('/api/applications', auth, async (req, res) => {
  try {
    const { post_id, note } = req.body;

    if (!isId(post_id)) {
      return res.status(400).json({ error: "Geçersiz ilan." });
    }

    const me = await User.findById(req.userId);
    if (!me || !['student', 'intern'].includes(me.role)) {
      return res.status(403).json({ error: "Sadece öğrenciler başvurabilir." });
    }

    const post = await InternshipPost.findById(post_id);
    if (!post) {
      return res.status(404).json({ error: "İlan bulunamadı." });
    }

    const already = await Application.findOne({ post_id, student_id: req.userId });
    if (already) {
      return res.status(409).json({ error: "Bu ilana zaten başvurdun." });
    }

    const application = await Application.create({
      post_id,
      post_position: post.position || (post.positions && post.positions[0]) || '',
      company_id: post.owner_id,
      company_name: post.company_name,
      student_id: req.userId,
      student_name: me.full_name,
      student_email: me.email,
      note
    });

    res.status(201).json(application);
  } catch (error) {
    console.error("Başvuru hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// Öğrencinin kendi başvuruları
app.get('/api/applications/mine', auth, async (req, res) => {
  try {
    const list = await Application.find({ student_id: req.userId }).sort({ created_at: -1 });
    res.json(list);
  } catch (error) {
    console.error("Başvurularım hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// Firmaya gelen başvurular
app.get('/api/applications/received', auth, async (req, res) => {
  try {
    const list = await Application.find({ company_id: req.userId }).sort({ created_at: -1 });
    res.json(list);
  } catch (error) {
    console.error("Başvuru listeleme hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// ---- Mesajlaşma ----

// Herkese açık profil alanları (şifre vb. asla dönmez)
function publicProfile(p) {
  p = p || {};
  return {
    job_title: p.job_title || '',
    company: p.company || '',
    job_description: p.job_description || '',
    university: p.university || '',
    department: p.department || '',
    birth_year: p.birth_year || '',
    experiences: Array.isArray(p.experiences) ? p.experiences : []
  };
}

// Mesajlaşılabilecek kişi listesi (şifre gibi bilgiler DÖNMEZ)
app.get('/api/directory', auth, async (req, res) => {
  try {
    let roles = String(req.query.roles || '').split(',').filter(Boolean);
    if (roles.includes('student')) roles.push('intern');
    const users = await User.find({ role: { $in: roles }, _id: { $ne: req.userId } })
      .select('full_name role profile');
    const out = users.map(u => {
      const p = u.profile || {};
      const parts = [];
      if (u.role === 'coach') parts.push('Kariyer Koçu');
      else if (u.role === 'graduate') {
        parts.push('Mezun');
        if (p.job_title) parts.push(p.job_title);
        if (p.university) parts.push(p.university);
      } else {
        parts.push('Öğrenci');
        if (p.department) parts.push(p.department);
      }
      return { _id: u._id, full_name: u.full_name, role: u.role, subtitle: parts.join(' · '), profile: publicProfile(p) };
    });
    res.json(out);
  } catch (error) {
    console.error("Rehber hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// Giriş yapmış kullanıcı başka birinin herkese açık profilini okur
app.get('/api/users/:id', auth, async (req, res) => {
  try {
    if (!isId(req.params.id)) return res.status(400).json({ error: "Geçersiz kullanıcı." });
    const u = await User.findById(req.params.id).select('full_name role profile');
    if (!u) return res.status(404).json({ error: "Kullanıcı bulunamadı." });
    res.json({ _id: u._id, full_name: u.full_name, role: u.role, profile: publicProfile(u.profile) });
  } catch (error) {
    console.error("Kullanıcı profili hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// Giriş yapan kişi ile diğer kişi arasındaki konuşma
app.get('/api/messages', auth, async (req, res) => {
  try {
    const other = req.query.other;
    if (!isId(other)) {
      return res.status(400).json({ error: "Geçersiz kullanıcı." });
    }
    const messages = await Message.find({
      $or: [
        { from_id: req.userId, to_id: other },
        { from_id: other, to_id: req.userId }
      ]
    }).sort({ created_at: 1 }).limit(500);
    res.json(messages);
  } catch (error) {
    console.error("Mesaj okuma hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/messages', auth, async (req, res) => {
  try {
    const { to_id, text } = req.body;
    if (!isId(to_id) || !text || !String(text).trim()) {
      return res.status(400).json({ error: "Mesaj boş olamaz." });
    }
    const message = await Message.create({
      from_id: req.userId,
      to_id,
      text: String(text).trim()
    });
    res.status(201).json(message);
  } catch (error) {
    console.error("Mesaj gönderme hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// Şifre yenileme (e-posta ile bağlantı gönderir). Giriş kodu şifreyi düz karşılaştırdığı
// için hashPassword şifreyi olduğu gibi döndürür.
require('./password_reset')(app, {
  User,
  hashPassword: async (plain) => plain
});

// Port Dinleme — Render kendi PORT değerini environment variable olarak verir
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`>>> API servisi aktif: port ${PORT}`);
});
