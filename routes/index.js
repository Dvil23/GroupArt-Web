var express = require('express');
var router = express.Router();
const db = require('../db')
const path = require('path');
const { nanoid } = require('nanoid')

const multer = require('multer')
const upload = multer()

const bcrypt = require('bcrypt')
const saltRounds = 10
const LessSaltRounds = 3
require('dotenv').config()

// Encriptar datos
const crypto = require('crypto');

const CLAVE = process.env.ENCRYPTION_KEY 
const IV = process.env.IV

function encriptar(texto) {
  const cipher = crypto.createCipheriv('aes-256-cbc', CLAVE, IV)
  let resultado = cipher.update(texto.toString(), 'utf8', 'hex')
  resultado += cipher.final('hex')
  return resultado
}

function desencriptar(encriptado) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', CLAVE, IV)
  let resultado = decipher.update(encriptado, 'hex', 'utf8')
  resultado += decipher.final('utf8')
  return resultado
}

//Si el usuario está logeado en la sesión, pasa los datos del usuario en local
router.use((req, res, next) => { 
  if (req.session && req.session.myuser) {
    res.locals.myuser = req.session.myuser;
  }
  next();
});

//Chequea si estás logeado
function isLoggedIn(req, res, next) {
  if (req.session && req.session.myuser) {
    next() 
  } else {
    res.redirect('/login')
  }
}

/* GET home page. */
router.get('/', function(req, res, next) {
  const invalidcode = req.query.error === 'invalidcode'
  res.render('inicio',{invalidcode});
});


/* GET register */
router.get('/register', function(req, res, next) {
  let { error } = req.query
  var message
  if (error == 0){
    message = "Todos los campos son obligatorios."
  }else if( error == 1){
    message = "Las contraseñas no coinciden."
  }else if (error == 2){
    message = "El nombre de usuario ya está en uso."
  }else if( error == 3){
    message = "El email ya está en uso."
  }

  let username = req.session.register_username || ""
  let email = req.session.register_email || ""
  console.log(username,email,"+",req.session.register_username,req.session.register_email)
  delete req.session.register_username
  delete req.session.register_email
  console.log("No")
  res.render('register',{message,username,email});

});


// POST register
router.post('/register',  function(req, res, next) {
  let { username, email, password, repeat_password } = req.body

  // Campos vacios
  if (username == "" || email == "" || password == "" || repeat_password == "" ) {
    saveDataRegister(req, username, email)
    res.redirect('/register?error=' + encodeURIComponent(0));
    return 
  }
  //Contraseñas no son iguales
  if (password != repeat_password ){
    saveDataRegister(req, username, email)
    res.redirect('/register?error=' + encodeURIComponent(1));
    return 
  }

  //Excepciones si username o email ya existe en la base de datos
  let consulta_check="SELECT * FROM users WHERE username = ? OR email = ?"

  db.query(consulta_check,[username,email],(error,results)=>{

    let user_already_exists = results.find(u => u.username === username)
    let email_already_exists = results.find(u => u.email === email)
    
    if (user_already_exists){
      saveDataRegister(req, username, email)
      res.redirect('/register?error=' + encodeURIComponent(2));
      return
      
    }else if (email_already_exists){
      saveDataRegister(req, username, email)
      res.redirect('/register?error=' + encodeURIComponent(3));
      return

    }else{ // Ningún error. Proceder al registro y redirección a página principal
      
      bcrypt.genSalt(saltRounds, function(err, salt) {
        bcrypt.hash(password, salt, function(err, hash) {
          
          let consulta_insert = "INSERT INTO users (username,email,password) VALUES (?,?,?)"
          db.query(consulta_insert, [username, email, hash], function(err, insertResult) {
            req.session.myuser = {
              id: insertResult.insertId,
              myusername: username,
              mypfp: 'default_pfp.jpg'
            }
            console.log("Sesión iniciada")
            return res.redirect('/')
           })
        })
      })
    }
  })
})

function saveDataRegister(req, username, email) {
  req.session.register_username = username || "";
  req.session.register_email = email || "";
}

/* GET login */
router.get('/login', function(req, res, next) {

  let {error} = req.query

  res.render('login',{ 
    error: error || "",
    email: req.session.loginEmail || "" 
  });

  delete req.session.loginEmail

});

// POST LOGIN
router.post('/login', function(req, res, next) {

  let {email, password} = req.body

  let consulta_check="SELECT * FROM users WHERE email = ?"
  db.query(consulta_check, [email], (error,results) => {
    if (results.length > 0){
      //Existe el email
      console.log(results)
      console.log("DIFF",results[0])
      //Hashear la contraseña y compararla con el resultado de la base de datos
      bcrypt.compare(password, results[0].password, (err, correct) => {
        if (correct){
          console.log("Sesión iniciada")
          req.session.myuser= {
            id: results[0].id,
            myusername: results[0].username,
            mypfp: results[0].pfp,
          }
          res.redirect('/')
          return

        }else{
          req.session.loginEmail = email
          res.redirect('/login?error=' + encodeURIComponent(true));
          return
        }
      })
    }else{
      // No exite el email
      req.session.loginEmail = email
      res.redirect('/login?error=' + encodeURIComponent(true));
      return
    }
  })
});






/* GET create groupartgroup */
router.get('/creategroup', isLoggedIn, function(req, res, next) {
  res.render('create');
});

// Funcion para generar codigo único
function generateUniqueCode(callback) {
    const code = nanoid(8)
    let consulta_check = "SELECT * FROM art_groups WHERE code = ?"

    db.query(consulta_check, [code], (error, results) => {
      if (error) return callback(error)

      if (results.length === 0) {
        // Código único
        callback(null, code)
      } else {
        // Código ya existe
        generateUniqueCode(callback)
      }
    });
  }

/* POST create group */
router.post('/creategroup', isLoggedIn, upload.single('icon'), async function(req, res, next) {

  let  { title, description, password, icon } = req.body

  console.log('Password recibido:', password)

  generateUniqueCode((err, uniqueCode) => {

    // Encriptar la contraseña con bcrypt y continuar con el insert
    bcrypt.hash(password, saltRounds, (err, hashed_password) => {

      let consulta_insert = "INSERT INTO art_groups (title, description, code, password) VALUES (?, ?, ?, ?)"
      db.query(consulta_insert, [title, description, uniqueCode, hashed_password], (err, result) => {

        res.redirect('/creategroup')
      });
    });
  });
});

// GET ACCESS GROUP
router.get('/accessgroup', isLoggedIn, function(req, res, next) {

  let { code } = req.query

  let consulta_check = "SELECT * FROM art_groups WHERE code = ?"

   db.query(consulta_check, [code], (error,results) => {
    // Intenta encontrar un grupo con ese código
    if (results.length>0){

      req.session.accessgrouptitle = results[0].title
      let encryptedid =  encriptar(results[0].id);
      res.redirect('/logingroup/'+encryptedid)
      return

    }else{
      res.redirect('/?error=invalidcode')
    }
   })
});

// GET LOGIN GROUP
router.get('/logingroup/:id', isLoggedIn, function(req, res, next) {
  let title = req.session.accessgrouptitle
  delete req.session.accessgrouptitle

  let { error } = req.query || false

  res.render('login_group',{title, error })
})

// POST LOGIN GROUP
router.post('/logingroup/:id', isLoggedIn, function(req, res, next) {
  let {password,group_title} = req.body
  let encryptedid = req.params.id
  let id = desencriptar(encryptedid)

  let consulta_check = "SELECT * FROM art_groups WHERE id = ?"
  db.query(consulta_check, [id], (error,results) => {
    bcrypt.compare(password, results[0].password, (err, correct) => {

      if(correct){
        let consulta_check_user = "SELECT * FROM members WHERE art_group_id = ?"
        db.query(consulta_check_user, [id], (error,results) => {

          if (!results.length){
            db.query("INSERT INTO members (users_id, art_group_id) VALUES (?, ?)", [req.session.myuser.id, id])
          }

          res.redirect('/group/'+ encryptedid )

        })
        
      }else{
        req.session.accessgrouptitle = group_title
        res.redirect('/logingroup/'+ encryptedid +'?error='+encodeURIComponent(true))
      }
    })
  })
})

router.get('/group/:id', isLoggedIn, function(req, res, next) {
  res.render('groupsview/group')
})
module.exports = router;
