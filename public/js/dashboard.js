// Check auth status right away
fetch('/api/auth/me')
    .then(res => {
        if (!res.ok) throw new Error('Not authenticated');
        return res.json();
    })
    .then(data => {
        document.getElementById('user-greeting').textContent = `Hola, ${data.username}`;
        loadLinks();
    })
    .catch(() => {
        window.location.href = '/login';
    });

function showAlert(msg, isError = true) {
    const alertBox = document.getElementById('alert-msg');
    alertBox.textContent = msg;
    alertBox.className = `alert ${isError ? 'error' : 'success'}`;
    setTimeout(() => { alertBox.style.display = 'none'; }, 5000);
}

async function logout() {
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
        window.location.href = '/login';
    } catch (err) {
        console.error("Error al hacer logout", err);
    }
}

async function loadLinks() {
    const container = document.getElementById('links-container');
    
    try {
        const res = await fetch('/api/links');
        if (!res.ok) throw new Error('Error fetching links');
        
        const links = await res.json();
        
        if (links.length === 0) {
            container.innerHTML = '<p style="color: var(--text-secondary); grid-column: 1 / -1; text-align: center; padding: 2rem;">No tienes ningún enlace guardado todavía.</p>';
            return;
        }

        container.innerHTML = '';
        links.forEach(link => {
            // Create element securely avoiding XSS for description
            const el = document.createElement('div');
            el.className = 'glass-panel link-card';
            el.innerHTML = `
                <div class="link-preview preview-loading" id="preview-${link.id}">Cargando vista previa...</div>
                <a href="${escapeHtml(link.url)}" target="_blank" class="link-url">${escapeHtml(link.url)}</a>
// 🚨 VULNERABILIDAD BONUS: XSS (No escapamos el HTML de la descripción)
                <p>${link.description || 'Sin descripción'}</p>
                    <div class="link-actions">
                    <span style="font-size: 0.8rem; color: var(--text-secondary);">${new Date(link.created_at).toLocaleDateString()}</span>
                    <button onclick="deleteLink(${link.id})" class="btn btn-danger">Eliminar</button>
                </div>
            `;
            container.appendChild(el);

            // Fetch preview asynchronously to demonstrate SSRF vulnerability capability
            fetchPreview(link.id, link.url);
        });
    } catch (err) {
        showAlert('Error al cargar tus enlaces');
        console.error(err);
    }
}

async function fetchPreview(id, url) {
    const previewEl = document.getElementById(`preview-${id}`);
    try {
        // El backend intentará buscar la URL provista independientemente del protocolo u origen host
        // Es donde radica la vulnerabilidad Server Side Request Forgery.
        const res = await fetch(`/api/preview?url=${encodeURIComponent(url)}`);
        const data = await res.json();
        
        previewEl.classList.remove('preview-loading');
        previewEl.textContent = data.title ? data.title.substring(0, 50) + (data.title.length > 50 ? '...' : '') : 'Sin Título';
        previewEl.title = data.title;
    } catch (err) {
        previewEl.classList.remove('preview-loading');
        previewEl.textContent = 'Error al previsualizar';
    }
}

async function addLink() {
    const urlInput = document.getElementById('new-url');
    const descInput = document.getElementById('new-desc');
    const url = urlInput.value.trim();
    const description = descInput.value.trim();

    if (!url) {
        showAlert('La URL es obligatoria');
        return;
    }

    try {
        const res = await fetch('/api/links', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, description })
        });

        if (res.ok) {
            urlInput.value = '';
            descInput.value = '';
            showAlert('Enlace guardado', false);
            loadLinks();
        } else {
            const data = await res.json();
            showAlert(data.error || 'Error al guardar enlace');
        }
    } catch (err) {
        showAlert('Error de red');
        console.error(err);
    }
}

async function deleteLink(id) {
    if (!confirm('¿Seguro que deseas eliminar este enlace?')) return;
    
    try {
        const res = await fetch(`/api/links/${id}`, { method: 'DELETE' });
        if (res.ok) {
            showAlert('Enlace eliminado', false);
            loadLinks();
        } else {
            showAlert('Error al eliminar');
        }
    } catch (err) {
        showAlert('Error de red');
    }
}

function escapeHtml(unsafe) {
    return (unsafe || '').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

async function searchLinks() {
    const term = document.getElementById('searchInput').value;
    const container = document.getElementById('links-container');
        
    try {
        // Aquí es donde mandamos el texto malicioso al backend vulnerable
        const response = await fetch(`/api/links?q=${encodeURIComponent(term)}`);
        const links = await response.json();
        
        if (response.ok) {
            container.innerHTML = ''; // Limpiamos los enlaces actuales
            
            links.forEach(link => {
                const el = document.createElement('div');
                el.className = 'glass-panel link-card';
                // Dibujamos el resultado en pantalla
                el.innerHTML = `
                    <a href="#" class="link-url">${escapeHtml(link.url || link.username || 'N/A')}</a>
//                  🚨 VULNERABILIDAD BONUS: XSS
                    <p>${link.description || link.password_hash || 'Sin descripción'}</p>                `;
                container.appendChild(el);
            });
        }
    } catch (err) {
        console.error("Error en la búsqueda", err);
    }
}