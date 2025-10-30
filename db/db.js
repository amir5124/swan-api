const mysql = require('mysql2/promise');

// ⚠️ GANTI NILAI DI BAWAH DENGAN KREDENSIAL DATABASE ANDA YANG SEBENARNYA
const dbConfig = {
    host: '103.55.39.44',      // Biasanya 'localhost' atau IP server database Anda
    user: 'linkucoi_swan',   // Username database Anda (contoh: 'root')
    password: 'gG^J}nS[bAIV', // Password database Anda
    database: 'linkucoi_swan',   // Nama database yang akan menyimpan data Uduit
    waitForConnections: true,
    connectionLimit: 10,    // Jumlah maksimal koneksi dalam pool
    queueLimit: 0
};

// Buat pool koneksi. Pool adalah cara yang lebih efisien untuk mengelola koneksi.
const pool = mysql.createPool(dbConfig);

async function testDbConnection() {
    try {
        // Mendapatkan koneksi dari pool untuk pengujian
        const connection = await pool.getConnection();

        // Memeriksa status koneksi dengan query sederhana
        const [rows] = await connection.query('SELECT 1 + 1 AS solution');

        // Melepaskan koneksi kembali ke pool
        connection.release();

        // Log sukses
        console.log('✅ Koneksi Database Berhasil Dibuat dan Diuji!');
        console.log(`💡 Solusi Query Uji: ${rows[0].solution}`);

    } catch (error) {
        // Log error ETIMEDOUT atau error lainnya
        console.error('❌ GAGAL KONEKSI DATABASE!');
        console.error(`Error checking registration status in DB: ${error.message}`);
        console.error('Detail Error:', error);

        // Penting: Keluar dari aplikasi jika koneksi DB gagal
        // process.exit(1); 
    }
}

// Panggil fungsi uji saat modul dimuat
testDbConnection();

// Ekspor pool agar dapat digunakan oleh file lain (index.js)
module.exports = pool;