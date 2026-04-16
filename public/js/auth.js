
        // Tab switching logic based on url parameters
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('tab') === 'register') {
            switchTab('register');
        }

        function switchTab(tab) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.form-section').forEach(sec => sec.classList.remove('active'));
            
            document.getElementById(`tab-${tab}`).classList.add('active');
            document.getElementById(`${tab}-section`).classList.add('active');
            hideAlert();
        }

        function showAlert(msg, isError = true) {
            const alertBox = document.getElementById('alert-msg');
            alertBox.textContent = msg;
            alertBox.className = `alert ${isError ? 'error' : 'success'}`;
        }

        function hideAlert() {
            const alertBox = document.getElementById('alert-msg');
            alertBox.style.display = 'none';
        }

        // Handle Login
        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = e.target.querySelector('button');
            const originalText = btn.textContent;
            btn.textContent = 'Verificando...';
            btn.disabled = true;

            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;

            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await res.json();
                
                if (res.ok) {
                    window.location.href = '/dashboard';
                } else {
                    showAlert(data.error || 'Error al iniciar sesión');
                }
            } catch (err) {
                showAlert('Error de conexión con el servidor');
            } finally {
                btn.textContent = originalText;
                btn.disabled = false;
            }
        });

        // Handle Register
        document.getElementById('register-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = e.target.querySelector('button');
            const originalText = btn.textContent;
            btn.textContent = 'Creando cuenta...';
            btn.disabled = true;

            const username = document.getElementById('reg-username').value;
            const password = document.getElementById('reg-password').value;

            try {
                const res = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await res.json();
                
                if (res.ok) {
                    showAlert('Cuenta creada exitosamente. Iniciando sesión...', false);
                    // Automatic login
                    await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });
                    setTimeout(() => {
                        window.location.href = '/dashboard';
                    }, 1000);
                } else {
                    showAlert(data.error || 'Error al registrarte');
                }
            } catch (err) {
                showAlert('Error de conexión con el servidor');
            } finally {
                btn.textContent = originalText;
                btn.disabled = false;
            }
        });
    