import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';

const db = await mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'Maria0295*',
  database: 'usuarios_hasheo',
  port: 3306
});

async function hashExistingPasswords() {
  const [users] = await db.query('SELECT user_id, contraseña FROM users');

  for (const user of users) {
    // bcrypt genera hashes que empiezan con $2, así que si no empieza así, no está hasheada
    if (!user.contraseña.startsWith('$2')) {
      const hashedPassword = await bcrypt.hash(user.contraseña, 10);
      await db.query('UPDATE users SET contraseña = ? WHERE user_id = ?', [
        hashedPassword,
        user.user_id
      ]);
      console.log(`Contraseña del usuario ${user.user_id} hasheada`);
    }
  }

  console.log('Proceso completado');
  process.exit();
}

hashExistingPasswords();
