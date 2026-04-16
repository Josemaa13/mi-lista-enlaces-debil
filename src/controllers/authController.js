const { getQuery, runQuery } = require('../config/db');

exports.register = async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });

    try {
        const existingUser = await getQuery('SELECT id FROM users WHERE username = ?', [username]);
        if (existingUser) return res.status(400).json({ error: 'Username already exists' });

        // 🚨 VULNERABILIDAD: Guardar contraseña en texto plano
        await runQuery('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, password]);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
};

exports.login = async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });

    try {
        const user = await getQuery('SELECT id, username, password_hash FROM users WHERE username = ?', [username]);
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });

        // 🚨 VULNERABILIDAD: Comparar contraseñas en texto plano
        const isValid = (password === user.password_hash);
        if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });

        req.session.userId = user.id;
        req.session.username = user.username;
        res.json({ message: 'Logged in successfully', username: user.username });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
};

exports.logout = (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ error: 'Could not log out' });
        res.json({ message: 'Logged out successfully' });
    });
};

exports.me = (req, res) => {
    res.json({ id: req.session.userId, username: req.session.username });
};