let Minio = require('minio')

let minio = new Minio.Client({
  endPoint: 'localhost',
  port: 9000,
  useSSL: false,
  accessKey: process.env.MINIO_ACCESS_KEY, 
  secretKey: process.env.MINIO_SECRET_KEY 
})


module.exports = minio