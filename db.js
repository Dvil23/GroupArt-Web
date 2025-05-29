const mysql = require('mysql2')
require('dotenv').config()


// Conexion a la base de datos con mis credenciales
const conexion = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
})

// Mensaje de error o success de conexion a la base de datos
conexion.connect((err) => {

  if (err) {console.log('Error base de datos:', err)} 
  else {console.log('Conexión a base de datos realizada correctamente')}
  
})

module.exports = conexion