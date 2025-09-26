require('dotenv').config();
const mongoose = require('mongoose');

const uri = process.env.MONGO_URI;

console.log("🔍 URI dari .env:", uri); // Ini untuk memastikan URI terbaca

mongoose.connect(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log("✅ Koneksi MongoDB BERHASIL!");
  mongoose.connection.close();
})
.catch((err) => {
  console.error("❌ Koneksi MongoDB GAGAL:", err.message);
});
