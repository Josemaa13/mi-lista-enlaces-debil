global.securityLogs = global.securityLogs || [];

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

// VER LOS LOGS
app.get('/admin_logs', (req, res) => {
    // 1. Comprobamos la cookie primero (A08)
    const cookies = req.headers.cookie || '';
    if (!cookies.includes('role=admin')) {
        return res.status(403).send('<h2>Acceso denegado. Solo administradores.</h2>');
    }

    // 2. Si es admin, le enviamos el HTML directamente como texto
    const html = `
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Panel de Monitorización - Admin</title>
        <style>
            body { font-family: monospace; background-color: #1e1e1e; color: #00ff00; padding: 20px; }
            textarea { width: 100%; height: 400px; background-color: #000; color: #00ff00; font-family: monospace; padding: 10px; border: 1px solid #555; }
            button { background-color: #00ff00; color: #000; padding: 10px 20px; border: none; cursor: pointer; font-weight: bold; margin-top: 10px; }
        </style>
    </head>
    <body>
        <h1>[ Panel Oculto de Logs del Sistema ]</h1>
        <p>Atención: La edición de estos registros alterará la auditoría del sistema.</p>
        
        <textarea id="logsArea" placeholder="Cargando logs..."></textarea><br>
        <button onclick="saveLogs()">Sobrescribir Registros</button>
        <span id="statusMessage" style="margin-left: 10px; color: yellow;"></span>

        <script>
            // Cargar logs al entrar
            fetch('/api/admin/logs')
                .then(res => res.json())
                .then(data => {
                    if(data.logs) document.getElementById('logsArea').value = data.logs.join('\\n');
                });

            // Guardar los logs manipulados
            function saveLogs() {
                const modifiedLogs = document.getElementById('logsArea').value;
                fetch('/api/admin/logs', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ newLogsText: modifiedLogs })
                })
                .then(res => res.json())
                .then(data => {
                    document.getElementById('statusMessage').innerText = data.message || 'Actualizado';
                    setTimeout(() => document.getElementById('statusMessage').innerText = '', 3000);
                });
            }
        </script>
    </body>
    </html>
    `;
    
    res.send(html);
});



app.get('/api/admin/logs', (req, res) => {
    const cookies = req.headers.cookie || '';
    if (cookies.includes('role=admin')) {
        // Simplemente devolvemos el array global
        res.json({ logs: global.securityLogs });
    } else {
        res.status(403).json({ error: 'Acceso denegado' });
    }
});

// ACTUALIZAR/MANIPULAR LOS LOGS (Tampering)
app.post('/api/admin/logs', (req, res) => {
    const cookies = req.headers.cookie || '';
    if (cookies.includes('role=admin')) {
        const { newLogsText } = req.body;
        if (newLogsText !== undefined) {
            // Convertimos el texto del área de logs de nuevo a un array
            // Cada línea será un elemento del array
            global.securityLogs = newLogsText.split('\n').filter(line => line.trim() !== '');
        }
        res.json({ message: 'Registros de seguridad actualizados (manipulados) con éxito.' });
    } else {
        res.status(403).json({ error: 'Acceso denegado' });
    }
});

// BORRAR LOS LOGS (🚨 VULNERABILIDAD A09)
app.delete('/api/admin/logs', (req, res) => {
    const cookies = req.headers.cookie || '';
    if (cookies.includes('role=admin')) {
        global.securityLogs = []; // Vaciamos el array
        res.json({ message: 'Todos los registros de seguridad han sido eliminados.' });
    } else {
        res.status(403).json({ error: 'Acceso denegado' });
    }
});


// 🚨 VULNERABILIDAD A10: Exceptional Conditions (Manejo inseguro de errores)
// Exponemos la traza de error completa (stack trace) al usuario final
app.use((err, req, res, next) => {
    console.error("💥 Error interceptado para A10:", err.message);
    res.status(500).send(`
        <div style="background-color: #ffe6e6; border: 1px solid red; padding: 20px; font-family: monospace;">
            <h2 style="color: red;">Internal Server Error 500</h2>
            <p>Unhandled exception occurred during request processing.</p>
            <hr>
            <h3>Stack Trace:</h3>
            <pre style="overflow-x: auto;">${err.stack}</pre>
        </div>
    `);
});

module.exports = app;