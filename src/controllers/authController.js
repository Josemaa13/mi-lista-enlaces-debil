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
    // 🚨 VULNERABILIDAD A06: Insecure Design
    // Diseño inseguro deliberado: No se implementan limitadores de peticiones 
    // (como express-rate-limit) ni mecanismos de bloqueo de cuenta tras intentos fallidos.
    // Esto permite ataques de fuerza bruta ilimitados.
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
    req.session.userId = user.id;
    req.session.username = user.username;

    // 🚨 VULNERABILIDAD A08: Software/Data Integrity Failures
    // Asignamos una cookie 'role' en texto plano, sin firma criptográfica (JWT o MAC).
    // El cliente puede modificarla libremente.
    const userRole = (user.username === 'admin') ? 'admin' : 'user';
    res.cookie('role', userRole); 

    res.json({ message: 'Logged in successfully', username: user.username });        
};

exports.logout = (req, res) => {
    // req.session.destroy(err => {
    //     if (err) return res.status(500).json({ error: 'Could not log out' });
    //     res.json({ message: 'Logged out successfully' });
    // });
    // 🚨 VULNERABILIDAD A07: Authentication Failures
    // Diseño inseguro: Fingimos cerrar la sesión de cara al usuario, 
    // pero NO la destruimos en el backend. La cookie sigue siendo válida.
    // Lo seguro sería hacer: req.session.destroy((err) => {...})
    
    // Simplemente devolvemos un mensaje de éxito dejando la sesión intacta
    res.json({ message: 'Logged out successfully' });
};

exports.me = (req, res) => {
    res.json({ id: req.session.userId, username: req.session.username });
};