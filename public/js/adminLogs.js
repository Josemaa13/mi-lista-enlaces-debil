
        // Cargar los logs al abrir la página
        fetch('/api/admin/logs')
            .then(res => {
                if (!res.ok) throw new Error('No autorizado');
                return res.json();
            })
            .then(data => {
                // Juntamos el array con saltos de línea para que se vea bien en el textarea
                document.getElementById('logsArea').value = data.logs.join('\n');
            })
            .catch(err => {
                document.getElementById('logsArea').value = "ERROR: Acceso denegado. Se requiere cookie role=admin.";
            });

        // Guardar los logs modificados
        function saveLogs() {
            const modifiedLogs = document.getElementById('logsArea').value;
            fetch('/api/admin/logs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ newLogsText: modifiedLogs })
            })
            .then(res => res.json())
            .then(data => {
                document.getElementById('statusMessage').innerText = data.message;
                setTimeout(() => document.getElementById('statusMessage').innerText = '', 3000);
            });
        }
    