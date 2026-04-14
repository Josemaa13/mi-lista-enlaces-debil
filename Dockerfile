# Usamos una imagen ligera de Node.js
FROM node:18-slim

# Instalamos la herramienta de línea de comandos de SQLite3 por si acaso
RUN apt-get update && apt-get install -y sqlite3 && rm -rf /var/lib/apt/lists/*

# Establecemos el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiamos primero los archivos de dependencias y las instalamos
COPY package*.json ./
RUN npm install

# Copiamos el resto del código del proyecto
COPY . .

# Creamos la carpeta para la base de datos e inicializamos el esquema
RUN mkdir -p /app/database
RUN sqlite3 /app/database/app.db < init_db.sql

# Damos permisos para que Node pueda modificar la base de datos
RUN chmod 777 /app/database /app/database/app.db

# Exponemos el puerto 3000 (estándar en Express)
EXPOSE 3000

# Comando para iniciar la aplicación
CMD ["npm", "start"]