
require("dotenv").config();

// Cargar otras variables de entorno necesarias
const { DB_USER, DB_PASSWORD, DB_HOST, DB_NAME, DB_PORT, PORT, SECRET_KEY } = process.env;

// Verifica que las variables esenciales estén definidas
if (!SECRET_KEY) {
  console.error("La clave secreta no está configurada correctamente");
  process.exit(1); // Termina el proceso si no está configurada
}

console.log("Clave secreta cargada correctamente");


const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const basePath = process.env.BASE_PATH || '';
const router = express.Router();

const app = express();
const path = require('path');
app.use(express.json());
app.use(cors());


// Conexión a PostgreSQL
const pool = new Pool({
  user: DB_USER,
  host: DB_HOST,
  database: DB_NAME,
  password: DB_PASSWORD,
  port: DB_PORT,
  ssl: {
    rejectUnauthorized: false
  }
})




// Aquí defines tus endpoints, por ejemplo:
// Obtener todos los usuarios
router.get("/api/usuarios", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM usuarios");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ...

// Servir frontend estático
app.use(express.static(path.join(__dirname, 'build/web')));

// Cualquier otra ruta que no sea API, devuelve index.html
router.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'build/web', 'index.html'));
});

// agregar a todo 
// finally {
//     client.release(); // ✅ Muy importante
//   }


////////////////////////////////////////////////////////////////////
////////////////////////////CRUD USUARIOS///////////////////////////
// Obtener todos los usuarios
app.get("/api/usuarios", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM usuarios")
    res.json(result.rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ✅ Ruta para crear nuevo usuario
app.post('/api/crearusuarios', async (req, res) => {
  const { nombre, apellido, email, cedula, password, rol } = req.body;

  try {
    // Encriptar password
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO usuarios (nombre, apellido, email, cedula, password, rol)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, nombre, apellido, email, cedula, rol`,
      [nombre, apellido, email, cedula, hashedPassword, rol]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    // Si es duplicado (PostgreSQL error code 23505)
    if (err.code === '23505') {
      return res.status(409).json({ error: 'La cédula o el email ya existen' });
    }
    res.status(500).json({ error: 'Error al crear usuario' });
  }
});

app.put('/api/usuarios/:id', async (req, res) => {
  const { id } = req.params;
  const { nombre, apellido, email, cedula, rol, password } = req.body;

  try {
    let query, values;

    if (password && password.trim() !== '') {
      // encripta nueva contraseña si la mandaron
      const hashedPassword = await bcrypt.hash(password, 10);
      query = `
        UPDATE usuarios
        SET nombre = $1, apellido = $2, email = $3, cedula = $4, rol = $5, password = $6
        WHERE id = $7
        RETURNING *`;
      values = [nombre, apellido, email, cedula, rol, hashedPassword, id];
    } else {
      // sin cambiar la contraseña
      query = `
        UPDATE usuarios
        SET nombre = $1, apellido = $2, email = $3, cedula = $4, rol = $5
        WHERE id = $6
        RETURNING *`;
      values = [nombre, apellido, email, cedula, rol, id];
    }

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al actualizar usuario' });
  }
});



///////ELIMINAR////
app.delete("/api/usuarios/:id", async (req, res) => {
  const { id } = req.params
  try {
    const result = await pool.query("DELETE FROM usuarios WHERE id = $1 RETURNING *", [id])
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" })
    }
    res.json({ mensaje: "Usuario eliminado correctamente" })
  } catch (error) {
    console.error("Error al eliminar usuario:", error)
    res.status(500).json({ error: "Error en el servidor" })
  }
})


//////////////////////////////////////////////////////////////////////////////




// Ruta para cerrar sesión
// Este endpoint es decorativo. NO invalida el JWT.
// Solo para cumplir con REST o para logging/auditoría.
router.post('/api/logout', (req, res) => {
  // (opcional) Si quieres registrar el logout para auditoría:
  const token = req.headers['authorization'];
  if (token) {
    // Puedes guardar el token, usuario, fecha, IP, etc. en tu DB/log
    console.log("Logout recibido para token:", token);
  }

  // Simplemente responde OK.
  res.status(200).json({ message: 'Sesión cerrada correctamente' });
});




// Registro de usuarios
router.post("/register", async (req, res) => {
  const { nombre, apellido, email, cedula, password, rol } = req.body;
  const userRole = rol || "estudiante"; // Por defecto estudiante

  if (!nombre || !apellido || !email || !cedula || !password) {
    return res.status(400).json({ error: "Todos los campos son obligatorios" });
  }

  try {
    // Encriptamos la contraseña antes de guardarla en la base de datos
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generamos el token de autenticación
    const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: "1h" });

    // Insertamos el usuario en la base de datos, incluyendo la cédula, nombre, apellido, email, password y token
    const result = await pool.query(
      "INSERT INTO usuarios (nombre, apellido, email, cedula, password, token, rol) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
      [nombre, apellido, email, cedula, hashedPassword, token, userRole]
    );

    // Recuperamos los datos del usuario insertado
    const user = result.rows[0];

    // Respondemos al cliente con el token y la información del usuario
    res.status(201).json({
      message: "Usuario registrado con éxito",
      token: token,
      usuario: {
        id: user.id,
        nombre: user.nombre,
        email: user.email,
        rol: user.rol // <-- AGREGA el campo rol en la respuesta
      }
    });

  } catch (err) {
    if (err.code === "23505") {
      // Error de correo duplicado
      res.status(400).json({ error: "El correo ya está registrado" });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});



// Login de usuario
router.post("/api/login", async (req, res) => {
  console.log("Solicitud de login recibida:", req.body); // <-- Agrega esto temporalmente

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email y contraseña son obligatorios" });
  }

  try {
    // Buscar el usuario por su email
    const result = await pool.query("SELECT * FROM usuarios WHERE email = $1", [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Correo no registrado" });
    }

    const user = result.rows[0];

    // Comparar la contraseña proporcionada con la almacenada
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    // Generar el token JWT
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });

    // Devolver el token y el nombre del usuario
    res.json({
      message: "Login exitoso",
      token: token,
      usuario: {
        id: user.id,
        nombre: user.nombre,
        email: user.email,
        rol: user.rol,
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});




//////////////////////////// WIFI CREDENTIALS CRUD //////////////////////////////

// Obtener el primer (o único) registro de WiFi
app.get('/api/wifi', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM wifi LIMIT 1');
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No hay credenciales guardadas' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener WiFi:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Crear nuevo registro de WiFi
app.post('/api/wifi', async (req, res) => {
  const { nombre, password } = req.body;
  if (!nombre || !password) {
    return res.status(400).json({ error: 'Nombre y contraseña son obligatorios' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO wifi (nombre, password) VALUES ($1, $2) RETURNING *',
      [nombre, password]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error al crear WiFi:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Actualizar registro de WiFi
app.put('/api/wifi/:id', async (req, res) => {
  const { id } = req.params;
  const { nombre, password } = req.body;
  if (!nombre || !password) {
    return res.status(400).json({ error: 'Nombre y contraseña son obligatorios' });
  }

  try {
    const result = await pool.query(
      'UPDATE wifi SET nombre = $1, password = $2 WHERE id = $3 RETURNING *',
      [nombre, password, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Registro WiFi no encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error al actualizar WiFi:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Eliminar registro de WiFi
app.delete('/api/wifi/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('DELETE FROM wifi WHERE id = $1 RETURNING *', [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Registro WiFi no encontrado' });
    }

    res.json({ mensaje: 'Registro WiFi eliminado correctamente' });
  } catch (error) {
    console.error('Error al eliminar WiFi:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});
/////////////////////////////////////////////////////////////





//////////////////////DATOS USUARIOS
// Obtener el perfil del usuario
app.get("/api/profile", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1]
  if (!token) {
    return res.status(401).json({ message: "Acceso denegado, token no proporcionado." })
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY)
    const result = await pool.query(
      "SELECT nombre, apellido, email, rol FROM usuarios WHERE id = $1",
      [decoded.id]
    )

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado." })
    }

    return res.json(result.rows[0])
  } catch (error) {
    return res.status(400).json({ message: "Token no válido." })
  }
})

/////////////////////// LUGARES AGREGAR, MODIFICAR, ELIMINAR //////////////////////////////////

// Obtener todos los lugares
router.get('/api/lugar', async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query("SELECT * FROM lugar");
    res.json(result.rows);
  } catch (err) {
    console.error('Error al obtener los lugares:', err);
    res.status(500).json({ error: 'Error al cargar los lugares' });
  } finally {
    client.release(); // 🔑 libera la conexión
  }
});


// Agregar un lugar
router.post('/api/lugar', async (req, res) => {
  try {
    const { nombre, fecha_creacion } = req.body;

    if (!nombre) {
      return res.status(400).json({ error: 'El nombre es obligatorio' });
    }

    const query = 'INSERT INTO lugar (nombre, fecha_creacion) VALUES ($1, $2) RETURNING *';
    const values = [nombre, fecha_creacion];

    const result = await pool.query(query, values);

    res.status(201).json({ mensaje: 'Lugar agregado', lugar: result.rows[0] });
  } catch (error) {
    console.error('Error al insertar en la base de datos:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Modificar lugar
router.put('/api/lugar/:id', async (req, res) => {
  const { id } = req.params;
  const { nombre, fecha_creacion } = req.body;

  if (!nombre || !fecha_creacion) {
    return res.status(400).json({ error: "Nombre y fecha de creación son obligatorios" });
  }

  try {
    const query = 'UPDATE lugar SET nombre = $1, fecha_creacion = $2 WHERE id = $3 RETURNING *';
    const values = [nombre, fecha_creacion, id];

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Lugar no encontrado" });
    }

    res.json({ mensaje: 'Lugar actualizado', lugar: result.rows[0] });
  } catch (error) {
    console.error('Error al actualizar el lugar:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Eliminar lugar
router.delete('/api/lugar/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('DELETE FROM lugar WHERE id = $1 RETURNING *', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Lugar no encontrado" });
    }

    res.json({ mensaje: 'Lugar eliminado', lugar: result.rows[0] });
  } catch (error) {
    console.error('Error al eliminar el lugar:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

///////////////////////////////////////////////////////////////////////////////////////


//////////////////////////// CATEGORIAS CRUD //////////////////////////////////

// 📌 Obtener todas las categorías (sin filtros)
router.get('/api/categorias', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM categoria');
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener categorías:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// 📌 Obtener categorías por lugar específico
router.get('/api/categorias/lugar', async (req, res) => {
  const { lugar_id } = req.query;
  try {
    let query = 'SELECT DISTINCT c.* FROM categoria c JOIN edificios e ON c.id = e.categoria_id';
    let params = [];

    if (lugar_id) {
      query += ' WHERE e.lugar_id = $1';
      params.push(lugar_id);
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener categorías por lugar:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});


// 📌 Agregar una nueva categoría
router.post('/api/categorias', async (req, res) => {
  try {
    const { nombre } = req.body;

    if (!nombre) {
      return res.status(400).json({ error: 'El nombre es obligatorio' });
    }

    const query = 'INSERT INTO categoria (nombre) VALUES ($1) RETURNING *';
    const values = [nombre];

    const result = await pool.query(query, values);

    res.status(201).json({ mensaje: 'Categoría agregada', categoria: result.rows[0] });
  } catch (error) {
    console.error('Error al agregar la categoría:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// 📌 Modificar una categoría
router.put('/api/categorias/:id', async (req, res) => {
  const { id } = req.params;
  const { nombre } = req.body;

  if (!nombre) {
    return res.status(400).json({ error: "El nombre es obligatorio" });
  }

  try {
    const query = 'UPDATE categoria SET nombre = $1 WHERE id = $2 RETURNING *';
    const values = [nombre, id];

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Categoría no encontrada" });
    }

    res.json({ mensaje: 'Categoría modificada', categoria: result.rows[0] });
  } catch (error) {
    console.error('Error al modificar la categoría:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// 📌 Eliminar una categoría
router.delete('/api/categorias/:id', async (req, res) => {
  const { id } = req.params;

  try {
    // Comprobar si la categoría existe antes de eliminarla
    const checkQuery = 'SELECT * FROM categoria WHERE id = $1';
    const checkResult = await pool.query(checkQuery, [id]);

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Categoría no encontrada' });
    }

    // Eliminar la categoría
    const deleteQuery = 'DELETE FROM categoria WHERE id = $1';
    await pool.query(deleteQuery, [id]);

    res.json({ mensaje: 'Categoría eliminada correctamente' });
  } catch (error) {
    console.error('Error al eliminar la categoría:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

//////////////////////////////////////////////////////////////////////
//////////////////////////////CRUD EDIFICACIONES//////////////////////////////////////////

// Obtener edificios filtrados por categoría
router.get('/api/edificios', async (req, res) => {
  const { categoria_id, lugar_id } = req.query; // Recibe la categoría y lugar seleccionados
  try {
    let query = 'SELECT * FROM edificios WHERE 1=1';
    let params = [];

    if (categoria_id) {
      params.push(categoria_id);
      query += ` AND categoria_id = $${params.length}`;
    }

    if (lugar_id) {
      params.push(lugar_id);
      query += ` AND lugar_id = $${params.length}`;
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener edificios:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});


// Obtener todas las edificaciones
router.get('/api/edificios', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM edificios');
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener edificaciones:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Agregar una edificación
router.post('/api/edificios', async (req, res) => {
  try {
    const { nombre, lugar_id, categoria_id } = req.body;

    if (!nombre || !lugar_id || !categoria_id) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }

    const query =
      'INSERT INTO edificios (nombre, lugar_id, categoria_id) VALUES ($1, $2, $3) RETURNING *';
    const values = [nombre, lugar_id, categoria_id];

    const result = await pool.query(query, values);
    res.status(201).json({ mensaje: 'Edificación agregada', edificio: result.rows[0] });
  } catch (error) {
    console.error('Error al agregar la edificación:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Modificar una edificación
router.put('/api/edificios/:id', async (req, res) => {
  const { id } = req.params;
  const { nombre, lugar_id, categoria_id } = req.body;

  try {
    const query =
      'UPDATE edificios SET nombre = $1, lugar_id = $2, categoria_id = $3 WHERE id = $4 RETURNING *';
    const values = [nombre, lugar_id, categoria_id, id];

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Edificación no encontrada' });
    }

    res.json({ mensaje: 'Edificación actualizada', edificio: result.rows[0] });
  } catch (error) {
    console.error('Error al modificar la edificación:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Eliminar una edificación
router.delete('/api/edificios/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const deleteQuery = 'DELETE FROM edificios WHERE id = $1 RETURNING *';
    const result = await pool.query(deleteQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Edificación no encontrada' });
    }

    res.json({ mensaje: 'Edificación eliminada correctamente' });
  } catch (error) {
    console.error('Error al eliminar la edificación:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

/////////////////////////////////////////////////////////////////
///////////////////// GESTION DE BLOQUES ////////////////////////

//Obtener laboratorios filtrados por bloque
router.get('/api/laboratorios', async (req, res) => {
  const { bloque_id } = req.query;
  try {
    let query = 'SELECT laboratorios FROM bloques WHERE id = $1';
    const result = await pool.query(query, [bloque_id]);
    if (result.rows.length > 0) {
      res.json(result.rows[0].laboratorios || []);
    } else {
      res.json([]);
    }
  } catch (error) {
    console.error('Error al obtener laboratorios:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Obtener detalles de un bloque por ID (incluyendo latitud y longitud)
router.get('/api/bloques/:id', async (req, res) => {
  const bloqueId = req.params.id;
  try {
    const query = `
      SELECT 
        b.id,
        b.nombre,
        b.descripcion,
        b.latitud,
        b.longitud,
        b.laboratorios,
        ed.nombre AS nombre_edificio
      FROM bloques b
      JOIN edificios ed ON b.edificios_id = ed.id
      WHERE b.id = $1
    `;
    const result = await pool.query(query, [bloqueId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Bloque no encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener detalles del bloque:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});


// Obtener todos los bloques
router.get('/api/bloques', async (req, res) => {
  const { edificio_id, lugar_id, categoria_id } = req.query;

  try {
    let query = `
      SELECT 
        bloques.id,
        bloques.nombre,
        bloques.descripcion,
        bloques.latitud,
        bloques.longitud,
        bloques.laboratorios,
        bloques.edificios_id,
        edificios.nombre AS nombre_edificio
      FROM bloques
      JOIN edificios ON bloques.edificios_id = edificios.id
    `;
    const values = [];
    const conditions = [];

    if (edificio_id) {
      values.push(edificio_id);
      conditions.push(`bloques.edificios_id = $${values.length}`);
    }

    if (lugar_id) {
      values.push(lugar_id);
      conditions.push(`edificios.lugar_id = $${values.length}`);
    }

    if (categoria_id) {
      values.push(categoria_id);
      conditions.push(`edificios.categoria_id = $${values.length}`);
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    const result = await pool.query(query, values);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener bloques:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});






// Agregar un bloque
router.post('/api/bloques', async (req, res) => {
  try {
    let { nombre, descripcion, latitud, longitud, edificios_id, laboratorios } = req.body;

    if (!nombre || !edificios_id) {
      return res.status(400).json({ error: 'El nombre y el edificio son obligatorios' });
    }

    // Si laboratorios no es un array, inicializarlo como un array vacío
    if (!Array.isArray(laboratorios)) {
      laboratorios = [];
    }

    const query = `
      INSERT INTO bloques (nombre, descripcion, latitud, longitud, edificios_id, laboratorios) 
      VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`;
    const values = [nombre, descripcion, latitud, longitud, edificios_id, `{${laboratorios.join(',')}}`]; // Convertimos la lista a formato PostgreSQL

    const result = await pool.query(query, values);
    res.status(201).json({ mensaje: 'Bloque agregado', bloque: result.rows[0] });
  } catch (error) {
    console.error('Error al agregar el bloque:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});


// Modificar un bloque
router.put('/api/bloques/:id', async (req, res) => {
  const { id } = req.params;
  const { nombre, descripcion, latitud, longitud, edificios_id, laboratorios } = req.body;

  try {
    const query = `
      UPDATE bloques 
      SET nombre = $1, descripcion = $2, latitud = $3, longitud = $4, edificios_id = $5, laboratorios = $6 
      WHERE id = $7 RETURNING *`;
    const values = [nombre, descripcion, latitud, longitud, edificios_id, laboratorios, id];

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Bloque no encontrado' });
    }

    res.json({ mensaje: 'Bloque actualizado', bloque: result.rows[0] });
  } catch (error) {
    console.error('Error al actualizar el bloque:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Eliminar un bloque
router.delete('/api/bloques/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const checkQuery = 'SELECT * FROM bloques WHERE id = $1';
    const checkResult = await pool.query(checkQuery, [id]);

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Bloque no encontrado' });
    }

    const deleteQuery = 'DELETE FROM bloques WHERE id = $1';
    await pool.query(deleteQuery, [id]);

    res.json({ mensaje: 'Bloque eliminado correctamente' });
  } catch (error) {
    console.error('Error al eliminar el bloque:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

///////////////////////////////////////////////////////////////
/////////////////////////EVALUCIONES CRUD/////////////////////
// Obtener todas las evaluaciones
router.get('/api/evaluaciones', async (req, res) => {
  try {
    const query = `
      SELECT 
          e.id,
          e.nombre,
          e.lugar_id,
          l.nombre AS lugar_nombre,
          e.categoria_id,
          c.nombre AS categoria_nombre,
          e.edificio_id,
          ed.nombre AS edificio_nombre,
          e.bloque_id,
          b.nombre AS bloque_nombre,
          e.laboratorios,
          e.fecha_inicio,
          e.fecha_fin,
          e.horarios
      FROM evaluaciones e
      JOIN lugar l ON e.lugar_id = l.id
      JOIN categoria c ON e.categoria_id = c.id
      JOIN edificios ed ON e.edificio_id = ed.id
      JOIN bloques b ON e.bloque_id = b.id
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener evaluaciones:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Obtener detalles de un bloque por ID
router.get('/api/bloques/:id', async (req, res) => {
  const bloqueId = req.params.id;
  try {
    const query = `
      SELECT 
          b.id,
          b.nombre,
          b.descripcion,
          ed.nombre AS nombre_edificio,
          b.laboratorios
      FROM bloques b
      JOIN edificios ed ON b.edificios_id = ed.id
      WHERE b.id = $1
    `;
    const result = await pool.query(query, [bloqueId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Bloque no encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error al obtener detalles del bloque:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Crear nueva evaluación
router.post('/api/evaluaciones', async (req, res) => {
  const {
    nombre,
    lugar_id,
    categoria_id,
    edificio_id,
    bloque_id,
    laboratorios,
    fecha_inicio,
    fecha_fin,
    horarios
  } = req.body;

  try {
    const result = await pool.query(
      `INSERT INTO evaluaciones (
        nombre, lugar_id, categoria_id, edificio_id, bloque_id,
        laboratorios, fecha_inicio, fecha_fin, horarios
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [
        nombre,
        lugar_id,
        categoria_id,
        edificio_id,
        bloque_id,
        laboratorios,
        fecha_inicio,
        fecha_fin,
        horarios
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error al crear evaluación:', error);
    res.status(500).json({ error: 'Error al crear evaluación' });
  }
});

router.put('/api/evaluaciones/:id', async (req, res) => {
  const { id } = req.params;
  const { nombre, lugar_id, categoria_id, edificio_id, bloque_id, laboratorios, fecha_inicio, fecha_fin, horarios } = req.body;

  try {
    const result = await pool.query(
      `UPDATE evaluaciones SET
        nombre = $1, lugar_id = $2, categoria_id = $3, edificio_id = $4, bloque_id = $5,
        laboratorios = $6, fecha_inicio = $7, fecha_fin = $8, horarios = $9
      WHERE id = $10 RETURNING *`,
      [nombre, lugar_id, categoria_id, edificio_id, bloque_id, laboratorios, fecha_inicio, fecha_fin, horarios, id]
    );

    if (result.rowCount === 0) {
      res.status(404).json({ error: 'Evaluación no encontrada' });
    } else {
      res.json(result.rows[0]);
    }
  } catch (error) {
    console.error('Error al modificar evaluación:', error);
    res.status(500).json({ error: 'Error al modificar evaluación' });
  }
});

// Eliminar evaluación
router.delete('/api/evaluaciones/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('DELETE FROM evaluaciones WHERE id = $1', [id]);

    if (result.rowCount === 0) {
      res.status(404).json({ error: 'Evaluación no encontrada' });
    } else {
      res.json({ message: 'Evaluación eliminada correctamente' });
    }
  } catch (error) {
    console.error('Error al eliminar evaluación:', error);
    res.status(500).json({ error: 'Error al eliminar evaluación' });
  }
});


const port = process.env.PORT || 3000;
app.use(basePath, router);

app.listen(port, () => console.log(`Servidor escuchando en el puerto ${port}`));

// app.listen(PORT, 'localhost', () => console.log(`Servidor en http://localhost:${PORT}`));
// app.listen(PORT, '0.0.0.0', () => console.log(`Servidor en http://0.0.0.0:${PORT}`));



