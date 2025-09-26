    require('dotenv').config();
    const bcrypt = require('bcrypt');
    const crypto = require('crypto');
    const fs = require('fs');
    const path = require('path');

    const usersPath = path.join(__dirname, 'data', 'users.json');

    async function createAdmin() {
    const adminData = {
        id: crypto.randomUUID(),
        name: "Admin Utama",
        email: "admin@gmail.com",
        password: await bcrypt.hash("passwordAdmin123", 10),
        role: "admin",
        createdAt: new Date().toISOString()
    };

    let users = [];
    if (fs.existsSync(usersPath)) {
        users = JSON.parse(fs.readFileSync(usersPath));
    }

    users.push(adminData);
    fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
    console.log("Admin created successfully!");
    }

    createAdmin();