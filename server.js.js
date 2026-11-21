const dns = require('node:dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ---------------------------------------------------------------------------
// MongoDB bağlantısı
// Render'da MONGO_URI environment variable'ı varsa onu kullanır.
// Yoksa aşağıdaki tırnak içine ESKİ server.js'indeki bağlantı adresini yapıştır.
// ---------------------------------------------------------------------------
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://sudeturer2002_db_user:Sude21.08@cluster0.ibptagd.mongodb.net/is_radar?retryWrites=true&w=majority";

mongoose.connect(MONGO_URI)
  .then(() => console.log(">>> MongoDB Atlas veritabanına başarıyla bağlanıldı!"))
  .catch(err => console.error(">>> Bağlantı hatası:", err.message));

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
  // yeni alanlar (firma ilan formu)
  owner_id: String,       // ilanı açan firmanın kullanıcı id'si
  position: String,       // aranan pozisyon
  work_type: String,      // Yüz yüze / Uzaktan / Hibrit
  requirements: String,   // aranan nitelikler
  duration: String,       // staj süresi
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
  profile: Object,        // mezun profil bilgileri burada tutulur
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
  created_at: { type: Date, default: Date.now }
}));

const Message = mongoose.model('messages', new mongoose.Schema({
  from_id: String,
  to_id: String,
  text: String,
  created_at: { type: Date, default: Date.now }
}));

const isId = (v) => mongoose.isValidObjectId(v);

// ---------------------------------------------------------------------------
// Mevcut endpoint'ler (değişmedi)
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

app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    console.error("Kullanıcı çekme hatası detayı:", error);
    res.status(500).json({ error: error.message });
  }
});

// Kullanıcı Kaydı (Register)
app.post('/api/register', async (req, res) => {
  try {
    const { full_name, email, password, role } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "E-posta ve şifre zorunludur." });
    }

    const newUser = new User({
      full_name,
      email,
      password, // İleride güvenlik için bcrypt ile şifrelenebilir
      role: role || 'intern'
    });

    await newUser.save();
    res.status(201).json({ message: "Kayıt başarılı!", user: newUser });
  } catch (error) {
    console.error("Kayıt hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// Kullanıcı Girişi (Login)
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).json({ error: "E-posta veya şifre hatalı." });
    }

    res.json({ message: "Giriş başarılı!", user });
  } catch (error) {
    console.error("Giriş hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// FİRMA: ilan açma ve ilanlarını listeleme
// ---------------------------------------------------------------------------
app.post('/api/posts', async (req, res) => {
  try {
    const {
      owner_id, company_name, contact_email,
      position, city, work_type, requirements, duration, description
    } = req.body;

    if (!isId(owner_id) || !position || !city) {
      return res.status(400).json({ error: "Pozisyon ve şehir zorunludur." });
    }

    const owner = await User.findById(owner_id);
    if (!owner || owner.role !== 'company') {
      return res.status(403).json({ error: "Sadece firma hesapları ilan açabilir." });
    }

    const post = await InternshipPost.create({
      owner_id, company_name, contact_email,
      position, city, work_type, requirements, duration, description,
      // öğrenci ekranındaki eski alanlar da dolsun
      department: position,
      positions: [position]
    });

    res.status(201).json(post);
  } catch (error) {
    console.error("İlan açma hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/posts/company/:id', async (req, res) => {
  try {
    const posts = await InternshipPost.find({ owner_id: req.params.id }).sort({ created_at: -1 });
    res.json(posts);
  } catch (error) {
    console.error("Firma ilanları hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// BAŞVURULAR: öğrenci başvurur, firma kendi ilanlarına gelenleri görür
// ---------------------------------------------------------------------------
app.post('/api/applications', async (req, res) => {
  try {
    const { post_id, student_id, student_name, student_email, note } = req.body;

    if (!isId(post_id) || !isId(student_id)) {
      return res.status(400).json({ error: "Geçersiz ilan veya kullanıcı." });
    }

    const post = await InternshipPost.findById(post_id);
    if (!post) {
      return res.status(404).json({ error: "İlan bulunamadı." });
    }

    const already = await Application.findOne({ post_id, student_id });
    if (already) {
      return res.status(409).json({ error: "Bu ilana zaten başvurdun." });
    }

    const application = await Application.create({
      post_id,
      post_position: post.position || (post.positions && post.positions[0]) || '',
      company_id: post.owner_id,
      company_name: post.company_name,
      student_id, student_name, student_email, note
    });

    res.status(201).json(application);
  } catch (error) {
    console.error("Başvuru hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/applications/company/:id', async (req, res) => {
  try {
    const list = await Application.find({ company_id: req.params.id }).sort({ created_at: -1 });
    res.json(list);
  } catch (error) {
    console.error("Başvuru listeleme hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------------------------
// MEZUN: profil bilgileri
// ---------------------------------------------------------------------------
app.get('/api/profile/:id', async (req, res) => {
  try {
    if (!isId(req.params.id)) return res.status(400).json({ error: "Geçersiz kullanıcı." });
    const user = await User.findById(req.params.id).select('profile');
    if (!user) return res.status(404).json({ error: "Kullanıcı bulunamadı." });
    res.json(user.profile || {});
  } catch (error) {
    console.error("Profil okuma hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/profile/:id', async (req, res) => {
  try {
    if (!isId(req.params.id)) return res.status(400).json({ error: "Geçersiz kullanıcı." });
    const user = await User.findByIdAndUpdate(
      req.params.id,
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

// ---------------------------------------------------------------------------
// MESAJLAŞMA
// ---------------------------------------------------------------------------

// Mesajlaşılabilecek kişi listesi (şifre gibi bilgiler DÖNMEZ)
// Örnek: /api/directory?roles=student,coach
app.get('/api/directory', async (req, res) => {
  try {
    const roles = String(req.query.roles || '').split(',').filter(Boolean);
    const users = await User.find({ role: { $in: roles } }).select('full_name role');
    res.json(users);
  } catch (error) {
    console.error("Rehber hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// İki kişi arasındaki konuşma
app.get('/api/messages', async (req, res) => {
  try {
    const { me, other } = req.query;
    if (!isId(me) || !isId(other)) {
      return res.status(400).json({ error: "Geçersiz kullanıcı." });
    }
    const messages = await Message.find({
      $or: [
        { from_id: me, to_id: other },
        { from_id: other, to_id: me }
      ]
    }).sort({ created_at: 1 }).limit(500);
    res.json(messages);
  } catch (error) {
    console.error("Mesaj okuma hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/messages', async (req, res) => {
  try {
    const { from_id, to_id, text } = req.body;
    if (!isId(from_id) || !isId(to_id) || !text || !String(text).trim()) {
      return res.status(400).json({ error: "Mesaj boş olamaz." });
    }
    const message = await Message.create({
      from_id, to_id, text: String(text).trim()
    });
    res.status(201).json(message);
  } catch (error) {
    console.error("Mesaj gönderme hatası:", error);
    res.status(500).json({ error: error.message });
  }
});

// Port Dinleme — Render kendi PORT değerini environment variable olarak verir
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`>>> API servisi aktif: port ${PORT}`);
});
