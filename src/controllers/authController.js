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
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });

    try {
        const user = await getQuery('SELECT id, username, password_hash FROM users WHERE username = ?', [username]);
        
        // 🚨 VULNERABILIDAD A04: Texto plano
        const isValid = user ? (password === user.password_hash) : false;

        // Por seguridad en caso de que la variable global no se haya inicializado a tiempo
        global.securityLogs = global.securityLogs || [];

        if (!user || !isValid) {
            // 🚨 A09: Fallo de logs (Guardado en memoria volátil)
            global.securityLogs.push(`[WARN] Intento fallido: ${username} a las ${new Date().toISOString()}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }   

        // Registramos el éxito
        global.securityLogs.push(`[INFO] Login exitoso: ${username} a las ${new Date().toISOString()}`);

        req.session.userId = user.id;
        req.session.username = user.username;

        // 🚨 VULNERABILIDAD A08: Cookie insegura
        const userRole = (user.username === 'admin') ? 'admin' : 'user';
        res.cookie('role', userRole); 

        res.json({ message: 'Logged in successfully', username: user.username });
    } catch (err) {
        console.error("💥 ERROR EN LOGIN:", err); 
        res.status(500).json({ error: 'Internal server error' });
    }
};

exports.logout = (req, res) => {
    // 🚨 VULNERABILIDAD A07: Authentication Failures
    // Diseño inseguro: Fingimos cerrar la sesión de cara al usuario, 
    // pero NO la destruimos en el backend. La cookie sigue siendo válida.
    res.json({ message: 'Logged out successfully' });
};

exports.me = (req, res) => {
    res.json({ id: req.session.userId, username: req.session.username });
};