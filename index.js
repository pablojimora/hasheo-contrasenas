import express, { json } from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import bcrypt from 'bcrypt';

const app = express();
app.use(cors());
app.use(json());

// Conexión a MySQL local
const db = await mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'Maria0295*',
  database: 'usuarios_hasheo',
  port: 3306
});

// Obtener todos los usuarios (sin mostrar contraseñas)
app.get('/users', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT user_id, nombre FROM users');
    res.json(rows);
  } catch (err) {
    res.status(500).json(err);
  }
});

// Contar usuarios
app.get('/count', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT COUNT(*) AS numUsers FROM users');
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json(err);
  }
});

// Agregar usuario con contraseña hasheada
app.post('/users', async (req, res) => {
  const { nombre, contraseña } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(contraseña, 10);
    await db.query(
      'INSERT INTO users (nombre, contraseña) VALUES (?, ?)',
      [nombre, hashedPassword]
    );
    res.json({ message: 'Usuario agregado con contraseña protegida' });
  } catch (err) {
    res.status(500).json(err);
  }
});

// Actualizar usuario y re-hashear contraseña si se envía
app.put('/users/:id', async (req, res) => {
  const { id } = req.params;
  const { nombre, contraseña } = req.body;

  try {
    let query, params;

    if (contraseña) {
      const hashedPassword = await bcrypt.hash(contraseña, 10);
      query = 'UPDATE users SET nombre = ?, contraseña = ? WHERE user_id = ?';
      params = [nombre, hashedPassword, id];
    } else {
      query = 'UPDATE users SET nombre = ? WHERE user_id = ?';
      params = [nombre, id];
    }

    const [result] = await db.query(query, params);
    if (result.affectedRows === 0)
      return res.status(404).json({ message: 'Usuario no encontrado' });

    res.json({ message: 'Usuario actualizado' });
  } catch (err) {
    res.status(500).json(err);
  }
});

// Eliminar usuario
app.delete('/users/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.query('DELETE FROM users WHERE user_id = ?', [id]);
    if (result.affectedRows === 0)
      return res.status(404).json({ message: 'Usuario no encontrado' });

    res.json({ message: 'Usuario eliminado' });
  } catch (err) {
    res.status(500).json(err);
  }
});

// Ruta de login
app.post('/login', async (req, res) => {
  const { nombre, contraseña } = req.body;

  try {
    // Buscar usuario por nombre
    const [users] = await db.query('SELECT * FROM users WHERE nombre = ?', [nombre]);

    if (users.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const user = users[0];

    // Comparar contraseña enviada con el hash guardado
    const isMatch = await bcrypt.compare(contraseña, user.contraseña);

    if (!isMatch) {
      return res.status(401).json({ message: 'Contraseña incorrecta' });
    }

    // Si todo está bien
    res.json({ message: 'Login exitoso', usuario: { id: user.user_id, nombre: user.nombre } });

  } catch (err) {
    res.status(500).json(err);
  }
});

app.listen(3000, () =>
  console.log('Servidor corriendo en http://localhost:3000')
);
