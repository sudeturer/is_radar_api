const dns = require('node:dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB Bağlantı Adresi
 // MongoDB Standart Bağlantı Adresi (DNS Sorgusunu By-pass Eder)
const MONGO_URI = "mongodb+srv://sudeturer2002_db_user:Sude21.08@cluster0.ibptagd.mongodb.net/is_radar?retryWrites=true&w=majority";
mongoose.connect(MONGO_URI)
  .then(() => console.log(">>> MongoDB Atlas veritabanına başarıyla bağlanıldı!"))
  .catch(err => console.error(">>> Bağlantı hatası:", err.message));

// Koleksiyon Modelleri
const InternshipPost = mongoose.model('internship_posts', new mongoose.Schema({
  company_name: String,
  city: String,
  department: String,
  positions: [String],
  description: String,
  contact_email: String,
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
  created_at: { type: Date, default: Date.now }
}));

// API Endpointleri (Flutter'ın veri alacağı yerler)
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
// 1. Kullanıcı Kaydı (Register)
app.post('/api/register', async (req, res) => {
  try {
    const { full_name, email, password, role } = req.body;

    // Basit kontrol
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

// 2. Kullanıcı Girişi (Login)
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
// Port Dinleme
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`>>> API servisi aktif: http://localhost:${PORT}`);
});