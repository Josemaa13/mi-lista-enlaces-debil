const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');


const app = express();
const PORT = process.env.PORT || 3000;

// Setup Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'super_secret_key_for_this_vulnerable_app',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Initialize SQLite Database
const dbDir = path.join(__dirname, 'database');
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir);
}
const dbPath = path.join(dbDir, 'app.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to SQLite:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        // If init_db.sql exists and db is empty, we might want to run it, but Docker already does it.
        // Doing a quick check just in case it's run locally without Docker.
        db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users'", (err, row) => {
            if (!row) {
                const initScript = fs.readFileSync(path.join(__dirname, 'init_db.sql'), 'utf-8');
                db.exec(initScript, (err) => {
                    if (err) console.error("Error creating tables:", err);
                    else console.log("Database initialized from init_db.sql");
                });
            }
        });
    }
});

// Helper functions for DB queries
const runQuery = (query, params = []) => new Promise((resolve, reject) => {
    db.run(query, params, function (err) {
        if (err) reject(err);
        else resolve(this);
    });
});

const getQuery = (query, params = []) => new Promise((resolve, reject) => {
    db.get(query, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
    });
});

const allQuery = (query, params = []) => new Promise((resolve, reject) => {
    db.all(query, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
    });
});

// Middleware to check auth
const requireAuth = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

// --- ROUTES ---

// 1. Authentication

app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const existingUser = await getQuery('SELECT id FROM users WHERE username = ?', [username]);
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        "const passwordHash = await bcrypt.hash(password, 10);"
        "await runQuery('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, passwordHash]);"
        // 🚨 VULNERABILIDAD: Guardar contraseña en texto plano
        // Guardamos la contraseña directamente sin usar bcrypt
        await runQuery('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, password]);
        
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const user = await getQuery('SELECT id, username, password_hash FROM users WHERE username = ?', [username]);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        "const isValid = await bcrypt.compare(password, user.password_hash);"
        // 🚨 VULNERABILIDAD: Comparar contraseñas en texto plano
        const isValid = (password === user.password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Set session
        req.session.userId = user.id;
        req.session.username = user.username;
        
        res.json({ message: 'Logged in successfully', username: user.username });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ error: 'Could not log out' });
        res.json({ message: 'Logged out successfully' });
    });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
    res.json({ id: req.session.userId, username: req.session.username });
});

// 2. Links CRUD

// OBTENER ENLACES (VULNERABLE A SQL INJECTION)
app.get('/api/links', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const searchTerm = req.query.q; 

        let query = '';
        let links = [];

        if (searchTerm) {
            // 🚨 VULNERABILIDAD A03:2021-Injection (SQLi)
            // Concatenación directa del input del usuario en la sentencia SQL.
            query = `SELECT * FROM links WHERE user_id = ${userId} AND (description LIKE '%${searchTerm}%' OR url LIKE '%${searchTerm}%')`;
            
            // Ejecutamos la query directamente SIN parámetros de protección
            db.all(query, [], (err, rows) => {
                if (err) {
                    // Para ayudar al alumno a ver el error SQL (CWE-209), devolvemos el error exacto
                    return res.status(500).json({ error: err.message }); 
                }
                res.json(rows);
            });
        } else {
            // Comportamiento normal (sin búsqueda)
            db.all('SELECT * FROM links WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, rows) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                res.json(rows);
            });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/links', requireAuth, async (req, res) => {
    const { url, description } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    try {
        const result = await runQuery('INSERT INTO links (user_id, url, description) VALUES (?, ?, ?)', [req.session.userId, url, description]);
        const newLink = await getQuery('SELECT * FROM links WHERE id = ?', [result.lastID]);
        res.status(201).json(newLink);
    } catch (err) {
        res.status(500).json({ error: 'Failed to create link' });
    }
});

app.put('/api/links/:id', requireAuth, async (req, res) => {
    const linkId = req.params.id;
    const { url, description } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    try {
        // 🚨 VULNERABILIDAD A01: Broken Access Control (IDOR)
        // Quitamos la comprobación "AND user_id = ?" 
        // Ahora cualquiera con una sesión válida puede editar el enlace de otro si adivina su ID
        const link = await getQuery('SELECT id FROM links WHERE id = ?', [linkId]);
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }

        await runQuery('UPDATE links SET url = ?, description = ? WHERE id = ?', [url, description, linkId]);
        const updatedLink = await getQuery('SELECT * FROM links WHERE id = ?', [linkId]);
        res.json(updatedLink);
    } catch (err) {
        res.status(500).json({ error: 'Failed to update link' });
    }
});

app.delete('/api/links/:id', requireAuth, async (req, res) => {
    const linkId = req.params.id;

    try {
        // 🚨 VULNERABILIDAD A01: Broken Access Control (IDOR)
        // Igual que en el PUT, eliminamos la validación de propiedad del recurso.
        const link = await getQuery('SELECT id FROM links WHERE id = ?', [linkId]);
        if (!link) {
            return res.status(404).json({ error: 'Link not found' });
        }

        await runQuery('DELETE FROM links WHERE id = ?', [linkId]);
        res.json({ message: 'Link deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete link' });
    }
});

// 3. Preview Endpoint (Vulnerable to SSRF)
app.get('/api/preview', requireAuth, async (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) {
        return res.status(400).json({ error: 'URL parameter is missing' });
    }

    try {
        // [!] VULNERABLE CODE PIPELINE START [!]
        // Makes a server-side request without verifying host/port, allowing SSRF
        const response = await fetch(targetUrl);
        const html = await response.text();
        
        // Extract title using regex
        const titleMatch = html.match(/<title>([^<]*)<\/title>/i);
        const title = titleMatch ? titleMatch[1].trim() : 'Sin título disponible';
        // [!] VULNERABLE CODE PIPELINE END [!]

        res.json({ title });
    } catch (error) {
        // Also verbose errors can enumerate internal services
        console.error('SSRF Preview Error:', error.message);
        res.json({ title: 'Error al previsualizar (Posible host inalcanzable)' });
    }
});

// Handle non-existing API routes
app.use('/api', (req, res) => {
    res.status(404).json({ error: 'API Endpoint Not Found' });
});

// Route everything else to index.html for SPA-like behavior or specific pages
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));


app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
