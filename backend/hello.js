console.log("Memulai skrip test-gemini.js..."); // Baris 1: Tanda skrip dimulai

try {
    console.log("Baris 2: Mencoba memuat 'dotenv'...");
    require('dotenv').config();
    console.log("Baris 3: 'dotenv' berhasil di-load dan dikonfigurasi.");

    console.log("Baris 4: Mencoba memuat '@google/generative-ai'...");
    const { GoogleGenerativeAI } = require('@google/generative-ai');
    console.log("Baris 5: '@google/generative-ai' SDK berhasil di-load.");

    console.log("Baris 6: Mencoba membaca GEMINI_API_KEY dari process.env...");
    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey || apiKey.trim() === "") { // Ditambahkan pengecekan apiKey kosong
        console.error("GAGAL (Baris 7): GEMINI_API_KEY tidak ditemukan di .env atau nilainya kosong!");
        console.log("Pastikan file .env ada di direktori E:\\eminent-auth\\backend\\ dan berisi baris GEMINI_API_KEY=API_KEY_ANDA_YANG_VALID");
        console.log("Isi process.env.GEMINI_API_KEY saat ini:", apiKey); // Log nilai apiKey
        process.exit(1); // Keluar dari skrip jika API key tidak ada
    }

    console.log("BERHASIL (Baris 8): GEMINI_API_KEY ditemukan. Key dimulai dengan:", apiKey.substring(0, 7) + "...");

    console.log("Baris 9: Mencoba menginisialisasi GoogleGenerativeAI dengan API Key...");
    const genAI = new GoogleGenerativeAI(apiKey);
    console.log("Baris 10: GoogleGenerativeAI SDK berhasil diinisialisasi.");

    async function runTest() {
        console.log("Baris 11: Memulai fungsi async runTest()...");
        try {
            console.log("Baris 12: Mencoba mendapatkan model 'gemini-1.5-flash'...");
            const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
            console.log("Baris 13: Model 'gemini-1.5-flash' berhasil didapatkan.");

            const prompt = "Sebutkan satu fakta menarik tentang Indonesia.";
            console.log(`Baris 14: Mencoba mengirim prompt: "${prompt}"`);

            const result = await model.generateContent(prompt);
            console.log("Baris 15: Panggilan API Gemini (generateContent) selesai.");

            const response = result.response;
            const text = response.text();
            console.log("-----------------------------------------");
            console.log("Respons dari Gemini (Baris 16):", text);
            console.log("-----------------------------------------");

        } catch (error) {
            console.error("ERROR di dalam runTest() (Baris 17): Error saat memanggil API Gemini:", error.message);
            if (error.name === 'GoogleGenerativeAIError') { // Cek jika ini error spesifik dari SDK
                console.error("Detail Error Google AI:", error);
            } else if (error.stack) {
                console.error("Stack Trace:", error.stack);
            }
        } finally {
            console.log("Baris 18: Fungsi runTest() selesai dieksekusi (baik sukses maupun gagal).");
        }
    }

    console.log("Baris 19: Akan memanggil fungsi runTest()...");
    runTest().then(() => {
        console.log("Baris 20: Pemanggilan runTest() selesai (promise telah resolved).");
    }).catch(e => {
        console.error("ERROR setelah pemanggilan runTest() (promise di-reject) (Baris 21):", e);
    });

} catch (e) {
    console.error("ERROR Global di luar try-catch utama (Baris 22):", e.message);
    if (e.stack) {
        console.error("Stack Trace Global:", e.stack);
    }
} finally {
    console.log("Baris 23: Skrip test-gemini.js akan segera berakhir.");
}