const { db, getQuery, runQuery } = require('../config/db');

exports.getLinks = async (req, res) => {
    try {
        const userId = req.session.userId;
        const searchTerm = req.query.q; 

        if (searchTerm) {
            // 🚨 VULNERABILIDAD A03:2021-Injection (SQLi)
            const query = `SELECT * FROM links WHERE user_id = ${userId} AND (description LIKE '%${searchTerm}%' OR url LIKE '%${searchTerm}%')`;
            db.all(query, [], (err, rows) => {
                if (err) return res.status(500).json({ error: err.message }); 
                res.json(rows);
            });
        } else {
            db.all('SELECT * FROM links WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, rows) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                res.json(rows);
            });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
};

exports.createLink = async (req, res) => {
    const { url, description } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    try {
        const result = await runQuery('INSERT INTO links (user_id, url, description) VALUES (?, ?, ?)', [req.session.userId, url, description]);
        const newLink = await getQuery('SELECT * FROM links WHERE id = ?', [result.lastID]);
        res.status(201).json(newLink);
    } catch (err) {
        res.status(500).json({ error: 'Failed to create link' });
    }
};

exports.updateLink = async (req, res) => {
    const linkId = req.params.id;
    const { url, description } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    try {
        // 🚨 VULNERABILIDAD A01: Broken Access Control (IDOR)
        const link = await getQuery('SELECT id FROM links WHERE id = ?', [linkId]);
        if (!link) return res.status(404).json({ error: 'Link not found' });

        await runQuery('UPDATE links SET url = ?, description = ? WHERE id = ?', [url, description, linkId]);
        const updatedLink = await getQuery('SELECT * FROM links WHERE id = ?', [linkId]);
        res.json(updatedLink);
    } catch (err) {
        res.status(500).json({ error: 'Failed to update link' });
    }
};

exports.deleteLink = async (req, res) => {
    const linkId = req.params.id;
    try {
        // 🚨 VULNERABILIDAD A01: Broken Access Control (IDOR)
        const link = await getQuery('SELECT id FROM links WHERE id = ?', [linkId]);
        if (!link) return res.status(404).json({ error: 'Link not found' });

        await runQuery('DELETE FROM links WHERE id = ?', [linkId]);
        res.json({ message: 'Link deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete link' });
    }
};

exports.previewLink = async (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) return res.status(400).json({ error: 'URL parameter is missing' });

    try {
        // 🚨 VULNERABILIDAD SSRF
        const response = await fetch(targetUrl);
        const html = await response.text();
        const titleMatch = html.match(/<title>([^<]*)<\/title>/i);
        const title = titleMatch ? titleMatch[1].trim() : 'Sin título disponible';
        res.json({ title });
    } catch (error) {
        console.error('SSRF Preview Error:', error.message);
        res.json({ title: 'Error al previsualizar (Posible host inalcanzable)' });
    }
};