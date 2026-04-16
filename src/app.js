const express = require('express');
const session = require('express-session');
const path = require('path');

// Importamos las rutas
const authRoutes = require('./routes/authRoutes');
const linkRoutes = require('./routes/linkRoutes');

const app = express();

// Middlewares estándar
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public'))); // Ajustado para salir de src/
app.use(session({
    secret: 'super_secret_key_for_this_vulnerable_app',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } 
}));

// 🚨 VULNERABILIDAD A02: Security Misconfiguration (Middlewares globales inseguros)
app.use((req, res, next) => {
    res.setHeader('X-Powered-By', 'Express/4.18.2 Node.js/18.x'); 
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('X-Debug-Mode', 'Enabled');
    next();
});

// Montamos las rutas de la API
app.use('/api/auth', authRoutes);
app.use('/api/links', linkRoutes); // Presta atención, ahora la ruta base es /api/links

// Handle non-existing API routes
app.use('/api', (req, res) => {
    res.status(404).json({ error: 'API Endpoint Not Found' });
});

// Rutas del Frontend
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, '../public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, '../public', 'dashboard.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../public', 'index.html')));
// Añade esto en tu archivo de rutas principales (o donde tengas las de API)

app.get('/api/admin/users', (req, res) => {
    // 🚨 VULNERABILIDAD A08: Confianza ciega en datos del cliente
    // Leemos la cookie directamente sin verificar si ha sido alterada
    const cookies = req.headers.cookie || '';
    
    if (cookies.includes('role=admin')) {
        // Si dice que es admin, le creemos y le damos los datos sensibles
        db.all('SELECT id, username, password_hash FROM users', [], (err, rows) => {
            if (err) return res.status(500).json({ error: 'Error' });
            res.json({ success: true, message: 'Panel de Admin', data: rows });
        });
    } else {
        res.status(403).json({ error: 'Acceso denegado. Solo para administradores.' });
    }
});
module.exports = app;