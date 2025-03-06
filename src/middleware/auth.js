const jwt = require("jsonwebtoken");

const authMiddleware = (req, res, next) => {
  // Extraer el token del encabezado "Authorization" y eliminar el prefijo "Bearer "
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ message: "Acceso denegado, token no proporcionado" });
  }

  try {
    // Verificar el token usando JWT_SECRET
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified; // Guardar el usuario verificado en la solicitud
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "El token ha expirado" });
    }
    // Otros errores de JWT (como token mal formado)
    return res.status(400).json({ message: "Token no válido o mal formado" });
  }
};

module.exports = authMiddleware;
