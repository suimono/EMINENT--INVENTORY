require('dotenv').config();
// Memuat variabel lingkungan dari file .env. Pastikan ini adalah baris kode pertama.
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } = require("@google/generative-ai");



// --- INISIALISASI APLIKASI EXPRESS ---
const app = express();

// --- KONFIGURASI GOOGLE GEMINI AI ---
let genAI;
let generativeModel;

// Instruksi sistem untuk gaya AI (gaya netizen meme receh)
const systemInstructionText = "Selamat datang di Eminent Inventory. Sistem ini dirancang untuk membantu Anda mengelola aset dengan mudah dan aman. Masukkan alamat Gmail dan kata sandi Anda untuk login. Jika belum memiliki akun, silakan hubungi administrator.";


if (process.env.GEMINI_API_KEY) {
    try {
        genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
        generativeModel = genAI.getGenerativeModel({
            model: "gemini-1.5-flash-latest",
            safetySettings: [
                { category: HarmCategory.HARM_CATEGORY_HARASSMENT, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
                { category: HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
                // Tambahkan kategori lain jika diperlukan
            ],
            systemInstruction: {
                role: "system",
                parts: [{ text: systemInstructionText }],
            }
        });
        console.log("✅ Layanan Google Gemini AI berhasil diinisialisasi dengan instruksi sistem.");
    } catch (error) {
        console.error("❌ Gagal menginisialisasi Google Gemini AI:", error.message);
        generativeModel = null; // Pastikan model null jika inisialisasi gagal
    }
} else {
    console.warn("⚠️ PERINGATAN: Variabel lingkungan 'GEMINI_API_KEY' tidak ditemukan di .env. Fitur AI Chatbot tidak akan berfungsi dengan Gemini.");
    generativeModel = null;
}

// --- MIDDLEWARE KEAMANAN & PARSING ---
// Helmet: Mengamankan header HTTP
app.use(helmet());
// Mongo Sanitize: Mencegah injeksi operator NoSQL
app.use(mongoSanitize());
// Express.json: Mengurai body JSON dengan batasan ukuran
app.use(express.json({ limit: '10kb' }));








// CORS: Mengaktifkan Cross-Origin Resource Sharing
app.use(cors({
    origin: '*'
}));
















// Rate Limiting: Membatasi permintaan untuk mencegah brute-force/DDoS sederhana
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 menit
    max: 100, // Batasi setiap IP menjadi 100 permintaan per 15 menit
    message: 'Terlalu banyak permintaan dari IP ini, silakan coba lagi nanti ya. Jangan nge-spam, bro!',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', apiLimiter); // Terapkan batas laju ke semua rute yang diawali /api/

// --- KONEKSI MONGODB ---
const MONGO_URI = process.env.MONGO_URI;



mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ MongoDB terhubung dengan sukses!'))
    .catch(err => {
        console.error('❌ Kesalahan koneksi MongoDB:', err.message);
        console.error('Pastikan MONGO_URI di .env sudah benar dan MongoDB Atlas dapat diakses (cek IP whitelist jika di cloud).');
        process.exit(1); // Keluar dari proses Node.js jika koneksi database gagal kritis
    });

// --- DEFINISI SKEMA DAN MODEL MONGOOSE ---
// Saran: Untuk aplikasi yang lebih besar, model-model ini sebaiknya dipisah ke folder /models
// Contoh: /models/Asset.js, /models/User.js, /models/ForgotPassword.js

// Skema untuk Aset
const assetSchema = new mongoose.Schema({
    kodeAset: {
        type: String,
        required: [true, 'Kode aset wajib diisi'],
        unique: true,
        trim: true,
        uppercase: true, // Otomatis ubah kode aset jadi huruf besar
        match: [/^[A-Z0-9-]+$/, 'Kode aset hanya boleh berisi huruf A-Z, angka 0-9, dan tanda hubung (-)'],
    },
    namaAset: { type: String, required: [true, 'Nama aset wajib diisi'], trim: true },
    jumlah: { type: Number, required: [true, 'Jumlah wajib diisi'], min: [1, 'Jumlah minimal 1'], default: 1 },
    lokasi: { type: String, required: [true, 'Lokasi wajib diisi'], trim: true },
    tanggal: {
        type: String, // Bisa diubah ke Date type jika ingin operasi tanggal yang kompleks
        required: [true, 'Tanggal perolehan wajib diisi'],
        trim: true,
        match: [/^\d{4}-\d{2}-\d{2}$/, 'Format tanggal harus YYYY-MM-DD'],
    },
    alasan: { type: String, required: [true, 'Alasan pengajuan wajib diisi'], trim: true },
    kategori: { type: String, required: [true, 'Kategori wajib diisi'], trim: true },
    imageName: { type: String, default: 'Tidak ada gambar' },
    status: {
        type: String,
        enum: {
            values: ['Menunggu Persetujuan', 'Disetujui', 'Ditolak'],
            message: 'Status tidak valid. Pilih antara Menunggu Persetujuan, Disetujui, atau Ditolak.',
        },
        default: 'Menunggu Persetujuan',
    },
    tanggalKeluar: { type: String, default: null }, // Bisa diubah ke Date
    penerima: { type: String, default: null },
}, { timestamps: true }); // `timestamps` otomatis menambahkan `createdAt` dan `updatedAt`

const Asset = mongoose.model('Asset', assetSchema);

// Skema untuk Pengguna
const userSchema = new mongoose.Schema({
    name: { type: String, required: [true, 'Nama pengguna wajib diisi'], trim: true },
    email: {
        type: String,
        required: [true, 'Email wajib diisi'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Format email tidak valid'],
    },
    password: { type: String, required: [true, 'Password wajib diisi'], minlength: [6, 'Password minimal 6 karakter'], select: false }, // `select: false` agar password tidak ikut saat query default
    role: {
        type: String,
        enum: { values: ['admin', 'user'], message: 'Peran tidak valid. Pilih antara admin atau user.' },
        default: 'user',
    },
    position: { type: String, default: 'Staff', trim: true },
    avatarUrl: { type: String, default: null },
    verified: { type: Boolean, default: false }, // Set default ke false, lalu bisa diubah setelah verifikasi email (opsional)
}, { timestamps: true });

// Pre-save hook untuk hashing password
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) { // Hanya hash jika password diubah atau baru
        this.password = await bcrypt.hash(this.password, 12);
    }
    next();
});

const User = mongoose.model('User', userSchema);

// Skema untuk Permintaan Lupa Kata Sandi
const forgotPasswordSchema = new mongoose.Schema({
    email: { type: String, required: true, lowercase: true, trim: true },
    token: { type: String, required: true, unique: true },
    expires: { type: Date, required: true },
    used: { type: Boolean, default: false },
}, { timestamps: true });

const ForgotPassword = mongoose.model('ForgotPassword', forgotPasswordSchema);

// --- KONFIGURASI PENGIRIMAN EMAIL (NODEMAILER) ---
const transporter = nodemailer.createTransport({
    service: 'gmail', // Bisa diganti dengan SMTP server lain
    pool: true, // Gunakan connection pool untuk performa lebih baik
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    tls: { rejectUnauthorized: process.env.NODE_ENV === 'production' } // Hanya reject self-signed certs di produksi
});

// Verifikasi koneksi server email saat startup
transporter.verify((error) => {
    if (error) {
        console.error('❌ Koneksi server email gagal. Pastikan konfigurasi EMAIL_USER dan EMAIL_PASS benar, dan Gmail mengizinkan akses aplikasi kurang aman atau App Password jika 2FA aktif.');
        console.error('Detail Error Nodemailer:', error.message);
    } else {
        console.log('✅ Server email Nodemailer siap dan berhasil terhubung.');
    }
});

// --- JWT UTILITY FUNCTIONS ---
const jwtUtils = {
    generateToken: (userId, role, name) => {
        const payload = { id: userId, role };
        if (name) payload.name = name;
        // console.log(`[JWT] Membuat token untuk userId: ${userId}, role: ${role}`); // Hapus ini di produksi
        return jwt.sign(
            payload,
            process.env.JWT_SECRET || 'your-default-strong-secret-key-for-dev-ONLY-DONT-USE-IN-PROD', // Kunci rahasia dari .env
            { expiresIn: process.env.JWT_EXPIRES_IN || '1h' } // Waktu kedaluwarsa token
        );
    },
    verifyToken: (token) => {
        try {
            return jwt.verify(token, process.env.JWT_SECRET || 'your-default-strong-secret-key-for-dev-ONLY-DONT-USE-IN-PROD');
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new Error('Token sudah kedaluwarsa. Silakan login kembali.');
            }
            if (error.name === 'JsonWebTokenError') {
                throw new Error('Token tidak valid. Autentikasi gagal.');
            }
            // Error lainnya
            throw new Error('Autentikasi gagal: Masalah pada token.');
        }
    }
};

// --- MIDDLEWARE KUSTOM ---
// Saran: Untuk aplikasi yang lebih besar, middleware ini bisa dipisah ke folder /middleware
// Contoh: /middleware/validateInputs.js, /middleware/auth.js, /middleware/errorHandler.js

/**
 * Middleware untuk memvalidasi input wajib.
 * @param {Array<string>} requiredFields - Daftar nama field yang wajib ada di req.body.
 */
const validateInputs = (requiredFields) => (req, res, next) => {
    const missingFields = requiredFields.filter(field => {
        const value = req.body[field];
        return value === undefined || value === null || (typeof value === 'string' && value.trim() === '');
    });

    if (missingFields.length > 0) {
        return res.status(400).json({ success: false, message: `Kolom wajib diisi hilang atau kosong: ${missingFields.join(', ')}. Tolong dilengkapi!` });
    }
    next();
};

/**
 * Middleware untuk otentikasi pengguna menggunakan JWT.
 * Menetapkan `req.user` dengan payload token yang di-decode.
 */
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: 'Autentikasi diperlukan. Format token harus "Bearer [token]".' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ success: false, message: 'Token tidak ditemukan setelah "Bearer ".' });
    }

    try {
        const decoded = jwtUtils.verifyToken(token);
        req.user = decoded; // Menambahkan payload pengguna ke objek request
        console.log(`[AUTH] User ID: ${req.user.id}, Role: ${req.user.role} terautentikasi.`);
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: error.message || 'Token tidak valid atau kedaluwarsa.' });
    }
};

/**
 * Middleware untuk otorisasi berdasarkan peran pengguna.
 * Harus digunakan setelah middleware `authenticate`.
 * @param {Array<string>} allowedRoles - Array peran yang diizinkan (e.g., ['admin', 'user']).
 */
const authorize = (allowedRoles = []) => {
    return (req, res, next) => {
        // req.user harus sudah ada dari middleware authenticate
        if (!req.user || !req.user.role) {
            console.warn(`[AUTH] User ID: ${req.user ? req.user.id : 'N/A'} mencoba akses tanpa peran.`);
            return res.status(403).json({ success: false, message: 'Akses ditolak: Informasi peran pengguna tidak tersedia.' });
        }

        if (allowedRoles.length && !allowedRoles.includes(req.user.role)) {
            console.warn(`[AUTH] User ID: ${req.user.id} dengan peran '${req.user.role}' mencoba akses rute terlarang untuk peran: ${allowedRoles.join(',')}.`);
            return res.status(403).json({ success: false, message: 'Akses ditolak: Kamu nggak punya izin, Bos. Ini bukan area kamu!' });
        }
        next();
    };
};

// --- AUTHENTICATION ENDPOINTS ---
// Saran: Endpoint ini sebaiknya dipisah ke folder /routes/auth.js

app.post('/api/auth/register', validateInputs(['name', 'email', 'password']), async (req, res, next) => {
    let { name, email, password, isAdmin, adminKey } = req.body;
    email = email.toLowerCase().trim();
    name = name.trim();
    let determinedRole = 'user'; // Default role

    console.log(`[REGISTER] Menerima permintaan registrasi untuk email: ${email}`);

    try {
        // Pengecekan email duplikat sudah ditangani oleh Mongoose unique validator

        // Penanganan pendaftaran admin
        if (isAdmin === true) {
            if (!process.env.ADMIN_SECRET_KEY) {
                console.error("❌ ERROR SERVER: ADMIN_SECRET_KEY tidak diatur di .env. Pendaftaran admin tidak aman.");
                return res.status(500).json({ success: false, message: 'Konfigurasi server untuk pendaftaran admin belum komplit.' });
            }
            if (adminKey === process.env.ADMIN_SECRET_KEY) {
                determinedRole = 'admin';
                console.log(`[REGISTER] AdminKey valid. Pengguna ${email} didaftarkan sebagai ADMIN.`);
            } else {
                console.warn(`[REGISTER] AdminKey TIDAK VALID untuk ${email}. Pendaftaran tetap sebagai user biasa.`);
                return res.status(403).json({ success: false, message: 'Kunci rahasia admin salah. Jangan coba-coba jadi admin kalau bukan haknya!' });
            }
        }

        const newUser = new User({
            name,
            email,
            password, // Password akan di-hash oleh pre-save hook di skema
            role: determinedRole,
            position: determinedRole === 'admin' ? 'Administrator Sistem' : 'Staff',
            avatarUrl: `https://placehold.co/100x100/${Math.floor(Math.random()*16777215).toString(16)}/FFFFFF?text=${name.substring(0,2).toUpperCase()}`
        });

        await newUser.save();
        console.log(`[REGISTER] Pengguna baru berhasil disimpan: ${newUser.email} (${newUser.role}).`);

        // Kirim email selamat datang
        const currentYear = new Date().getFullYear();
        const supportEmail = process.env.SUPPORT_EMAIL || 'dukungan@eminentinventory.com';
        const dashboardLink = `${process.env.FRONTEND_URL || 'http://127.0.0.1:5500'}/admin.html`;
        const htmlBody = `<!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Selamat Datang di Eminent Inventory!</title><style>body{margin:0;padding:0;background-color:#f4f7f6;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}.email-container{max-width:600px;margin:20px auto;background-color:#fff;border-radius:8px;overflow:hidden;box-shadow:0 4px 15px rgba(0,0,0,.1);border:1px solid #e0e0e0}.email-header{background-color:#4A90E2;padding:30px 20px;text-align:center;color:#fff}.email-header h1{margin:0;font-size:28px;font-weight:600}.email-body{padding:30px 25px;color:#333;line-height:1.6;font-size:16px}.email-body p{margin:0 0 15px}.email-body .highlight{color:#4A90E2;font-weight:700}.cta-button{display:inline-block;background-color:#5cb85c;color:#fff!important;padding:12px 25px;text-decoration:none;border-radius:5px;font-size:16px;font-weight:700;margin-top:15px;margin-bottom:20px;text-align:center}.email-footer{background-color:#f0f0f0;padding:20px 25px;text-align:center;font-size:12px;color:#777;border-top:1px solid #e0e0e0}.email-footer p{margin:5px 0}.email-footer a{color:#4A90E2;text-decoration:none}@media screen and (max-width:600px){.email-container{width:100%!important;margin:0 auto!important;border-radius:0!important;border:none!important}.email-body{padding:20px 15px!important}.email-header{padding:25px 15px!important}.email-header h1{font-size:24px!important}}</style></head><body><table width="100%" border="0" cellspacing="0" cellpadding="0" bgcolor="#f4f7f6"><tr><td align="center" valign="top"><div class="email-container"><div class="email-header"><h1>Selamat Datang!</h1></div><div class="email-body"><p>Halo <strong class="highlight">${newUser.name}</strong>,</p><p>Kami sangat senang menyambut Anda di <strong class="highlight">Eminent Inventory</strong>! Terima kasih telah bergabung dengan kami.</p><p>Eminent Inventory dirancang untuk merevolusi cara Anda mengelola inventaris – menjadikannya lebih intuitif, efisien, dan cerdas. Kami percaya platform kami akan menjadi aset berharga bagi kelancaran operasional Anda.</p><div style="text-align:center"><a href="${dashboardLink}" class="cta-button" style="color:#fff">Mulai Kelola Inventaris</a></div><p>Jika Anda memiliki pertanyaan, membutuhkan bantuan, atau ingin memberikan masukan, tim dukungan kami selalu siap membantu. Anda dapat menghubungi kami melalui <a href="mailto:${supportEmail}" style="color:#4A90E2;text-decoration:none">${supportEmail}</a>.</p><p>Sekali lagi, selamat datang di keluarga Eminent Inventory!</p><br><p>Salam hangat,</p><p><strong>Tim Eminent Inventory</strong></p></div><div class="email-footer"><p>&copy; ${currentYear} Eminent Inventory. Semua Hak Cipta Dilindungi.</p><p>Jika Anda merasa menerima email ini karena kesalahan, mohon abaikan.</p><p>Eminent Inventory | Jalan Digital No. 1, Kota Cyber, Indonesia</p></div></div></td></tr></table></body></html>`;

        try {
            await transporter.sendMail({
                from: `"Eminent Inventory" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: `🎉 Selamat Datang di Eminent Inventory, ${newUser.name}!`,
                html: htmlBody
            });
            console.log(`[REGISTER] Email selamat datang terkirim ke ${email}`);
        } catch (emailError) {
            console.error(`[REGISTER] Gagal ngirim email selamat datang ke ${email}:`, emailError.message);
            // Jangan kasih tahu user kalau gagal ngirim email demi keamanan (mencegah enumerasi email)
        }

        res.status(201).json({
            success: true,
            message: `Registrasi berhasil sebagai ${newUser.role}! Cek emailmu buat konfirmasi, ya.`,
            user: { id: newUser._id, name: newUser.name, email: newUser.email, role: newUser.role, position: newUser.position, avatarUrl: newUser.avatarUrl }
        });

    } catch (error) {
        next(error); // Teruskan error ke middleware error handling global
    }
});

app.post('/api/auth/login', validateInputs(['email', 'password']), async (req, res, next) => {
    let { email, password, role } = req.body;
    email = email.toLowerCase().trim();
    const roleFromRequest = role ? role.toLowerCase().trim() : null;

    console.log(`[LOGIN] Permintaan login dari ${email} (role: ${roleFromRequest || 'auto-detect'}).`);

    try {
        const user = await User.findOne({ email }).select('+password'); // `+password` untuk mengambil field yang di-`select: false`
        if (!user) {
            console.log(`[LOGIN] Gagal: Email ${email} tidak ditemukan.`);
            return res.status(401).json({ success: false, message: 'Email atau password salah. Coba lagi, Gans!' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log(`[LOGIN] Gagal: Password salah untuk ${email}.`);
            return res.status(401).json({ success: false, message: 'Email atau password salah. Yakin itu akunmu?' });
        }

        // Validasi peran jika disediakan dari frontend
        if (roleFromRequest && user.role !== roleFromRequest) {
            console.warn(`[LOGIN] Peran tidak cocok untuk ${email}. Diminta: ${roleFromRequest}, Tersimpan: ${user.role}.`);
            return res.status(403).json({
                success: false,
                message: `Waduh, kamu login sebagai '${roleFromRequest}', tapi akun ini aslinya '${user.role}'. Pilih yang bener dong!`
            });
        }

        const token = jwtUtils.generateToken(user._id, user.role, user.name);
        console.log(`[LOGIN] Berhasil: Pengguna ${user.email} (${user.role}) berhasil login.`);
        res.json({
            success: true,
            message: 'Login berhasil! Selamat datang kembali!',
            token,
            user: { id: user._id, name: user.name, email: user.email, role: user.role, position: user.position, avatarUrl: user.avatarUrl }
        });

    } catch (error) {
        next(error); // Teruskan error ke middleware error handling global
    }
});

app.post('/api/auth/forgot-password', validateInputs(['email']), async (req, res, next) => {
    let { email } = req.body;
    email = email.toLowerCase().trim();

    console.log(`[FORGOT-PW] Permintaan reset password untuk email: ${email}.`);

    try {
        const user = await User.findOne({ email });

        if (user) {
            const token = crypto.randomBytes(32).toString('hex');
            const expires = new Date(Date.now() + 3600000); // Token valid 1 jam

            // Hapus token lama yang belum kedaluwarsa dan belum digunakan untuk email ini
            await ForgotPassword.deleteMany({
                email: email,
                expires: { $gt: new Date() },
                used: false
            });

            const newForgotPassword = new ForgotPassword({ email, token, expires }); // Mongoose akan mengkonversi Date otomatis
            await newForgotPassword.save();
            console.log(`[FORGOT-PW] Token reset password baru disimpan untuk ${email}.`);

            const resetLink = `${process.env.FRONTEND_URL || 'http://127.0.0.1:5500'}/reset-password.html?token=${token}&email=${encodeURIComponent(email)}`;
            const forgotPasswordHtmlBody = `<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background-color: #f9f9f9;"><div style="text-align: center; margin-bottom: 20px;"><h1 style="color: #4A90E2; font-size: 24px;">Permintaan Reset Password</h1></div><p style="font-size: 16px; color: #333;">Halo ${user.name},</p><p style="font-size: 16px; color: #333;">Kami menerima permintaan untuk mereset password akun Eminent Inventory Anda. Jika Anda merasa tidak melakukan permintaan ini, Anda dapat mengabaikan email ini.</p><p style="font-size: 16px; color: #333;">Untuk melanjutkan proses reset password, silakan klik tombol di bawah ini:</p><div style="text-align: center; margin: 30px 0;"><a href="${resetLink}" style="background-color: #4A90E2; color: white !important; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-size: 16px; font-weight: bold; display: inline-block;">Reset Password Saya</a></div><p style="font-size: 16px; color: #333;">Link reset password ini akan kedaluwarsa dalam <strong>1 jam</strong>.</p><p style="font-size: 16px; color: #333;">Jika Anda mengalami kesulitan atau tombol di atas tidak berfungsi, Anda juga dapat menyalin dan menempelkan URL berikut ke browser Anda:</p><p style="font-size: 14px; color: #555; word-break: break-all;">${resetLink}</p><hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;" /><p style="font-size: 14px; color: #777;">Terima kasih,</p><p style="font-size: 14px; color: #777;"><strong>Tim Eminent Inventory</strong></p></div>`;

            try {
                await transporter.sendMail({
                    from: `"Eminent Inventory Support" <${process.env.EMAIL_USER}>`,
                    to: email,
                    subject: 'Permintaan Reset Password Akun Eminent Inventory Anda',
                    html: forgotPasswordHtmlBody
                });
                console.log(`[FORGOT-PW] Email reset password terkirim ke ${email}`);
            } catch (emailError) {
                console.error(`[FORGOT-PW] Gagal ngirim email reset password ke ${email}:`, emailError.message);
                // Jangan kasih tahu user kalau gagal ngirim email demi keamanan (mencegah enumerasi email)
            }
        } else {
            console.log(`[FORGOT-PW] Permintaan reset password untuk email tidak terdaftar: ${email}.`);
        }
        // Selalu kirim pesan sukses generik untuk mencegah enumerasi email
        res.json({ success: true, message: 'Kalau emailmu terdaftar di sistem kami, cek inbox ya! Link reset password udah meluncur.' });
    } catch (error) {
        next(error); // Teruskan error ke middleware error handling global
    }
});

app.post('/api/auth/reset-password', validateInputs(['email', 'token', 'newPassword']), async (req, res, next) => {
    let { email, token, newPassword } = req.body;
    email = email.toLowerCase().trim();

    console.log(`[RESET-PW] Memproses reset password untuk email: ${email}.`);

    try {
        if (newPassword.length < 6) {
            return res.status(400).json({ success: false, message: 'Password baru minimal 6 karakter. Wajib itu!' });
        }

        // Cari token yang belum digunakan dan belum kedaluwarsa
        const forgotRequest = await ForgotPassword.findOne({
            email,
            token,
            used: false,
            expires: { $gt: new Date() } // expires > current time
        });

        if (!forgotRequest) {
            console.log(`[RESET-PW] Token tidak valid atau kedaluwarsa untuk ${email}.`);
            return res.status(400).json({ success: false, message: 'Link reset password tidak valid, sudah dipakai, atau udah kedaluwarsa. Cobain request ulang ya!' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            console.warn(`[RESET-PW] Pengguna tidak ditemukan untuk ${email} meskipun token valid.`);
            // Seharusnya tidak terjadi jika forgotRequest ditemukan, tapi sebagai pengaman
            return res.status(404).json({ success: false, message: 'Pengguna tidak ditemukan. Kok bisa ya?' });
        }

        // Update password dan tandai token sebagai sudah dipakai
        user.password = newPassword; // Pre-save hook akan hash password ini
        forgotRequest.used = true;
        forgotRequest.usedAt = new Date(); // Catat waktu penggunaan token

        await Promise.all([user.save(), forgotRequest.save()]); // Simpan secara paralel
        console.log(`[RESET-PW] Password berhasil direset dan token ditandai dipakai untuk ${email}.`);

        res.json({ success: true, message: 'Password berhasil direset! Sekarang bisa login lagi dengan password baru.' });
    } catch (error) {
        next(error); // Teruskan error ke middleware error handling global
    }
});

app.get('/api/auth/me', authenticate, async (req, res, next) => {
    console.log(`[ME] Mengambil profil untuk user ID: ${req.user.id}.`);
    try {
        // req.user.id berasal dari payload JWT
        const user = await User.findById(req.user.id).select('-password'); // Kecualikan password dari hasil
        if (!user) {
            console.warn(`[ME] Pengguna dengan ID ${req.user.id} tidak ditemukan meskipun token valid.`);
            return res.status(404).json({ success: false, message: 'Pengguna tidak ditemukan dari token yang valid. Aneh nih!' });
        }

        res.json({
            success: true,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                position: user.position,
                avatarUrl: user.avatarUrl,
                verified: user.verified
            }
        });
    } catch (error) {
        next(error); // Teruskan error ke middleware error handling global
    }
});

// --- API ROUTES UNTUK MANAJEMEN ASET ---
// Saran: Endpoint ini sebaiknya dipisah ke folder /routes/assets.js

// Mendapatkan semua aset (bisa diakses siapa saja yang terautentikasi)
app.get('/api/assets', authenticate, async (req, res, next) => {
    console.log(`[ASSET] GET semua aset oleh user ID: ${req.user.id}.`);
    try {
        const assets = await Asset.find();
        res.json(assets);
    } catch (error) {
        next(error);
    }
});

// Menambahkan aset baru (pengguna biasa atau admin)
app.post('/api/assets', authenticate, async (req, res, next) => {
    const { kodeAset, namaAset, jumlah, lokasi, tanggal, alasan, kategori, imageName } = req.body;
    console.log(`[ASSET] POST aset baru: ${namaAset} oleh user ID: ${req.user.id}.`);
    try {
        const newAsset = new Asset({
            kodeAset,
            namaAset,
            jumlah,
            lokasi,
            tanggal,
            alasan,
            kategori,
            imageName,
            status: 'Menunggu Persetujuan' // Status default untuk pengajuan baru
        });
        const savedAsset = await newAsset.save();
        console.log(`[ASSET] Aset baru berhasil disimpan: ${savedAsset.kodeAset}.`);
        res.status(201).json(savedAsset);
    } catch (error) {
        next(error); // Teruskan error ke middleware error handling global
    }
});

// Memperbarui aset (hanya admin)
app.put('/api/assets/:id', authenticate, authorize(['admin']), async (req, res, next) => {
    const { id } = req.params;
    console.log(`[ASSET] PUT update aset ID: ${id} oleh Admin ID: ${req.user.id}.`);
    try {
        const updatedAsset = await Asset.findByIdAndUpdate(id, req.body, {
            new: true, // Mengembalikan dokumen yang diperbarui
            runValidators: true // Jalankan validasi skema saat update
        });
        if (!updatedAsset) {
            console.warn(`[ASSET] Gagal update: Aset ID ${id} tidak ditemukan.`);
            return res.status(404).json({ success: false, message: 'Aset tidak ditemukan. Mungkin udah lenyap?' });
        }
        console.log(`[ASSET] Aset ID: ${id} berhasil diupdate.`);
        res.json(updatedAsset);
    } catch (error) {
        next(error);
    }
});

// Menghapus aset (hanya admin)
app.delete('/api/assets/:id', authenticate, authorize(['admin']), async (req, res, next) => {
    const { id } = req.params;
    console.log(`[ASSET] DELETE aset ID: ${id} oleh Admin ID: ${req.user.id}.`);
    try {
        const deletedAsset = await Asset.findByIdAndDelete(id);
        if (!deletedAsset) {
            console.warn(`[ASSET] Gagal hapus: Aset ID ${id} tidak ditemukan.`);
            return res.status(404).json({ success: false, message: 'Aset tidak ditemukan. Mau hapus apa hayoo?' });
        }
        console.log(`[ASSET] Aset ID: ${id} berhasil dihapus.`);
        res.json({ success: true, message: 'Aset berhasil dihapus. Bye-bye aset!' });
    } catch (error) {
        next(error);
    }
});


// --- API ROUTES UNTUK MANAJEMEN PENGGUNA (khusus admin) ---
// Saran: Endpoint ini sebaiknya dipisah ke folder /routes/users.js

// Mendapatkan semua pengguna (hanya admin)
app.get('/api/users', authenticate, authorize(['admin']), async (req, res, next) => {
    console.log(`[USER_MGMT] GET semua pengguna oleh Admin ID: ${req.user.id}.`);
    try {
        const users = await User.find().select('-password'); // Ambil semua user kecuali password
        res.json({ success: true, users });
    } catch (error) {
        next(error);
    }
});

// Memperbarui pengguna (hanya admin yang bisa update user lain)
app.put('/api/users/:id', authenticate, authorize(['admin']), async (req, res, next) => {
    const { id } = req.params;
    console.log(`[USER_MGMT] PUT update pengguna ID: ${id} oleh Admin ID: ${req.user.id}.`);
    const { name, email, role, position, avatarUrl, verified } = req.body;
    try {
        // Buat objek update, hanya sertakan field yang diizinkan dan tidak kosong
        const updateData = {};
        if (name !== undefined) updateData.name = name;
        if (email !== undefined) updateData.email = email;
        if (role !== undefined) updateData.role = role;
        if (position !== undefined) updateData.position = position;
        if (avatarUrl !== undefined) updateData.avatarUrl = avatarUrl;
        if (verified !== undefined) updateData.verified = verified;

        // Validasi email jika diupdate (pastikan tidak duplikat dan format benar)
        if (updateData.email && updateData.email.toLowerCase() !== (await User.findById(id)).email.toLowerCase()) {
            const existingUser = await User.findOne({ email: updateData.email.toLowerCase() });
            if (existingUser) {
                return res.status(409).json({ success: false, message: 'Email sudah dipakai pengguna lain. Nggak bisa kembar!' });
            }
        }
        
        const updatedUser = await User.findByIdAndUpdate(id, updateData, { new: true, runValidators: true }).select('-password');
        
        if (!updatedUser) {
            console.warn(`[USER_MGMT] Gagal update: Pengguna ID ${id} tidak ditemukan.`);
            return res.status(404).json({ success: false, message: 'Pengguna tidak ditemukan. Kayaknya hilang di semesta.' });
        }
        console.log(`[USER_MGMT] Pengguna ID: ${id} berhasil diupdate.`);
        res.json({ success: true, message: 'Data pengguna berhasil diupdate!', user: updatedUser });

    } catch (error) {
        next(error);
    }
});

// Menghapus pengguna (hanya admin)
app.delete('/api/users/:id', authenticate, authorize(['admin']), async (req, res, next) => {
    const { id } = req.params;
    console.log(`[USER_MGMT] DELETE pengguna ID: ${id} oleh Admin ID: ${req.user.id}.`);
    try {
        // Pastikan admin tidak menghapus dirinya sendiri
        if (req.user.id === id) {
            console.warn(`[USER_MGMT] Admin ID: ${req.user.id} mencoba menghapus akunnya sendiri.`);
            return res.status(403).json({ success: false, message: 'Nggak bisa hapus akunmu sendiri, Bro! Nanti siapa yang ngurusin?' });
        }

        const deletedUser = await User.findByIdAndDelete(id);
        if (!deletedUser) {
            console.warn(`[USER_MGMT] Gagal hapus: Pengguna ID ${id} tidak ditemukan.`);
            return res.status(404).json({ success: false, message: 'Pengguna tidak ditemukan. Udah keburu logout duluan kali ya?' });
        }
        console.log(`[USER_MGMT] Pengguna ID: ${id} berhasil dihapus.`);
        res.json({ success: true, message: 'Pengguna berhasil dihapus. Aman!' });
    } catch (error) {
        next(error);
    }
});


// --- AI CHATBOT ENDPOINT ---
// Rute ini tidak dilindungi authenticate jika Anda ingin AI bisa diakses publik (walau tidak disarankan)
// Jika AI perlu data aset atau user spesifik, perlu di-authenticate
app.post('/api/ai/chat', validateInputs(['prompt']), async (req, res, next) => {
    const { prompt, history } = req.body;
    const userId = req.user ? req.user.id : 'anonymous'; // Jika ada authenticate middleware di atas
    console.log(`[AI-CHAT] Permintaan dari ${userId} dengan prompt: "${prompt.substring(0, 50)}..."`);

    if (!generativeModel) {
        console.error("[AI-CHAT] Layanan Gemini AI tidak diinisialisasi. Cek GEMINI_API_KEY.");
        return res.status(503).json({
            success: false,
            message: "Layanan AI tidak tersedia saat ini. Mungkin AI-nya lagi istirahat minum kopi."
        });
    }

    try {
        // Format history untuk Gemini API (menyesuaikan format [ { role: 'user', parts: [{ text: '...' }] }, ... ] )
        const formattedHistory = history ? history.map(msg => ({
            role: msg.role,
            parts: Array.isArray(msg.parts) ? msg.parts : [{ text: String(msg.parts) }]
        })) : [];

        const chat = generativeModel.startChat({
            history: formattedHistory,
        });

        const result = await chat.sendMessage(prompt);
        const response = await result.response;

        // Cek respons AI untuk konten yang valid atau pemblokiran
        if (!response.candidates || response.candidates.length === 0 ||
            !response.candidates[0].content || !response.candidates[0].content.parts ||
            response.candidates[0].content.parts.length === 0 || !response.candidates[0].content.parts[0].text)
        {
            console.warn("[AI-CHAT] Respon Gemini tidak punya konten teks valid atau diblokir.");
            console.warn("[AI-CHAT] Prompt Feedback:", response.promptFeedback); // Log feedback dari AI
            let blockMessage = "Maaf, AI-nya lagi gak mood jawab nih. Coba pertanyaan lain deh.";
            if (response.promptFeedback && response.promptFeedback.blockReason) {
                blockMessage = `AI-nya protes karena alasan: "${response.promptFeedback.blockReason}". Coba ganti pertanyaannya biar akur.`;
                return res.status(400).json({ success: false, message: blockMessage });
            }
            if(response.candidates && response.candidates[0] && response.candidates[0].finishReason && response.candidates[0].finishReason !== 'STOP'){
                blockMessage = `AI-nya nyerah di tengah jalan karena: ${response.candidates[0].finishReason}. Coba pertanyaan yang lebih gampang.`;
                return res.status(400).json({ success: false, message: blockMessage });
            }
            return res.status(500).json({ success: false, message: blockMessage });
        }

        const aiResponseText = response.candidates[0].content.parts[0].text;
        console.log(`[AI-CHAT] Respon untuk ${userId}: "${aiResponseText.substring(0, 50)}..."`);
        res.json({ success: true, response: aiResponseText });

    } catch (error) {
        console.error("[AI-CHAT] Error saat komunikasi dengan Google Gemini API:", error.message);
        if (error.stack) console.error(error.stack);
        let errorMessage = "Terjadi kesalahan saat memproses permintaan AI. Mungkin AI-nya lagi nge-lag.";
        if (error.message && error.message.includes("API key not valid")) {
            errorMessage = "Kunci API Google Gemini nggak valid, Bos! Cek lagi di .env.";
        }
        next(new Error(errorMessage)); // Teruskan error ke middleware error handling global
    }
});


// --- HEALTH CHECK ENDPOINT ---
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        service: 'Eminent Backend Service (MongoDB & Gemini Integrated)',
        version: '1.6.0-alpha' // Contoh versi
    });
});

// --- GLOBAL ERROR HANDLING MIDDLEWARE ---
// Middleware ini harus diletakkan paling akhir, sebelum app.listen
app.use((err, req, res, next) => {
    console.error('😱 KESALAHAN SERVER TIDAK TERTANGANI:', err.stack || err.message || err);

    // Jika header sudah terkirim, serahkan ke default Express error handler
    if (res.headersSent) {
        return next(err);
    }

    let statusCode = err.statusCode || 500;
    let message = err.message || 'Terjadi kesalahan server internal. Server lagi pusing, Bro! Coba sebentar lagi.';

    // Penanganan error Mongoose spesifik
    if (err.name === 'CastError') {
        statusCode = 400;
        message = `Data yang diminta tidak valid (${err.path}: ${err.value}). Formatnya beda nih!`;
    } else if (err.name === 'ValidationError') {
        statusCode = 400;
        // Mongoose validation errors can have multiple messages
        const validationMessages = Object.values(err.errors).map(val => val.message);
        message = `Input tidak valid: ${validationMessages.join('. ')}`;
    } else if (err.code && err.code === 11000) { // Duplicate key error
        statusCode = 409;
        // Extract the duplicated field name from the error message
        const field = Object.keys(err.keyValue).join(', ');
        message = `Duplikasi data. '${field}' sudah ada, nih. Harus unik, ya!`;
    } else if (err.name === 'TokenExpiredError' || err.name === 'JsonWebTokenError') {
        statusCode = 401;
        message = err.message || 'Token tidak valid atau kedaluwarsa. Autentikasi ulang dong!';
    } else if (err.message && err.message.includes('Akses ditolak')) { // Custom authorization errors
        statusCode = 403;
        message = err.message;
    } else if (err.message && err.message.includes('Autentikasi diperlukan')) { // Custom authentication errors
        statusCode = 401;
        message = err.message;
    }

    res.status(statusCode).json({
        success: false,
        message: message
    });
});

// --- HANDLE 404 NOT FOUND ---
// Middleware ini harus diletakkan setelah semua rute API
app.use((req, res) => {
    if (!res.headersSent) {
        res.status(404).json({
            success: false,
            message: `Halaman atau endpoint yang kamu cari (${req.method} ${req.originalUrl}) nggak ketemu nih. Kayaknya nyasar!`
        });
    }
});


// --- START SERVER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server Eminent Inventory berjalan di port ${PORT}!`);
    console.log(`🌐 Lingkungan: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 URL Frontend diizinkan CORS: ${process.env.FRONTEND_URL || 'http://127.0.0.1:5500'}`);

    // Peringatan penting untuk variabel lingkungan di startup
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'your-default-strong-secret-key-for-dev-ONLY-DONT-USE-IN-PROD') {
        console.warn('⚠️ PERINGATAN: Variabel lingkungan "JWT_SECRET" tidak diatur di .env atau masih pakai nilai default. Ini TIDAK AMAN untuk produksi! Ganti dengan kunci acak yang kuat.');
    }
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        console.warn('⚠️ PERINGATAN: Variabel lingkungan "EMAIL_USER" atau "EMAIL_PASS" tidak diatur di .env. Fitur pengiriman email mungkin ngambek.');
    }
    if (!process.env.ADMIN_SECRET_KEY) {
        console.error('❌ KRITIKAL: Variabel lingkungan "ADMIN_SECRET_KEY" tidak diatur di .env. Fitur pendaftaran admin akan error atau tidak aman. HARUS DIATUR!');
    }
    if (!process.env.GEMINI_API_KEY) {
        console.error('❌ KRITIKAL: Variabel lingkungan "GEMINI_API_KEY" tidak diatur di .env. Fitur AI Chatbot dengan Gemini TIDAK AKAN BERFUNGSI.');
    } else if (!generativeModel) {
        console.error('❌ KRITIKAL: Gagal menginisialisasi model Gemini meskipun GEMINI_API_KEY ada. Cek error di atas. Fitur AI Chatbot TIDAK AKAN BERFUNGSI.');
    }
    if (process.env.NODE_ENV === 'production' && process.env.FRONTEND_URL && !process.env.FRONTEND_URL.startsWith('https://')) {
        console.warn('⚠️ PERINGATAN PRODUKSI: Dalam lingkungan produksi, sangat disarankan menggunakan HTTPS untuk FRONTEND_URL dan seluruh komunikasi API. Pastikan FRONTEND_URL dimulai dengan "https://".');
    }
});