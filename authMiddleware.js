// authMiddleware.js
const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env.SECRET_KEY;

function authRequired(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token no proporcionado' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded; // <<-- Puedes acceder a req.user en tus rutas
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// Middleware para admins
function adminRequired(req, res, next) {
  authRequired(req, res, function () {
    // Aquí, req.user.id ya existe gracias al anterior
    // Debes leer el usuario de la DB y revisar si es admin
    pool.query('SELECT rol FROM usuarios WHERE id = $1', [req.user.id])
      .then(result => {
        if (result.rows[0]?.rol === 'admin') {
          next();
        } else {
          res.status(403).json({ error: 'Solo administradores' });
        }
      })
      .catch(err => res.status(500).json({ error: 'Error interno' }));
  });
}

module.exports = { authRequired, adminRequired };
