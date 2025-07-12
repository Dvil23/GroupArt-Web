var express = require('express')
var router = express.Router()
const db = require('../db')
const path = require('path')
const { nanoid } = require('nanoid')

// Gestion de archivos en form
const multer = require('multer')
const upload = multer({ storage: multer.memoryStorage() })

// Subir archivos al servidor de imagenes local minio
const minio= require('../minio')

// Dayjs horario españa
const dayjs = require('dayjs')
const utc = require('dayjs/plugin/utc')
const timezone = require('dayjs/plugin/timezone')

dayjs.extend(utc)
dayjs.extend(timezone)

const Spain = dayjs().tz('Europe/Madrid')

//Mailer
const transporter = require("../mailer")

//uuid para tokens
const { v4: uuidv4 } = require('uuid')
const nodemailer = require("nodemailer")

// --------------------------ENCRIPTAR DATOS --------------------------

// Bcrypt (Seguro, pero no desencriptable)
const bcrypt = require('bcrypt')
const saltRounds = 10
const LessSaltRounds = 3
require('dotenv').config()

// crypto (Menos seguro, pero encriptable)
const crypto = require('crypto')

const CLAVE = process.env.ENCRYPTION_KEY 
const IV = process.env.IV

function encriptar(texto) {
  try{
    const cipher = crypto.createCipheriv('aes-256-cbc', CLAVE, IV)
    let resultado = cipher.update(texto.toString(), 'utf8', 'hex')
    resultado += cipher.final('hex')
    return resultado
  }catch(error){
    console.error("Fallo al encriptar:", error)
    return null
  }
}

function desencriptar(encriptado) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', CLAVE, IV)
  let resultado = decipher.update(encriptado, 'hex', 'utf8')
  resultado += decipher.final('utf8')
  return resultado
}

// -------------------------- SESSION --------------------------

//Si el usuario está logeado en la sesión, pasa los datos del usuario en local
router.use((req, res, next) => { 
  if (req.session && req.session.myuser) {
    res.locals.myuser = req.session.myuser
  }
  next()
})

//Check si estás logeado
function isLoggedIn(req, res, next) {
  if (!req.session || !req.session.myuser) {
    console.warn('Acceso no autorizado - sesión no válida')
    return res.redirect('/login')
  }

  if (!req.session.myuser.id || !req.session.myuser.myusername) {
    console.error('Sesión inválida o incompleta')
    return res.redirect('/login')
  }

  next()
}


// -------------------------- FUNCIONES --------------------------

//Check si eres miembro del grupo 
// Si envias true a la función significa que la página es solo para admin
function isMemberOfGroup(requiresAdmin = false) {
  return function(req, res, next) {

    let encrypted_art_group_id = req.params.id
    let art_group_id = desencriptar(encrypted_art_group_id)


    let consulta_check_member = "SELECT * FROM members WHERE users_id = ? AND art_group_id = ?"
    db.query(consulta_check_member, [req.session.myuser.id,art_group_id], (error, results) => {
      if (results.length > 0){

        //Check si es admin o superadmin
        req.isadmin = results[0].type === 1 || results[0].type === 2

        //Si no es admin, e intenta entrar en una página admin les devuelve al grupo
        if (requiresAdmin && !req.isadmin){
          console.log("NO es admin")
          return res.redirect('/group/' + encrypted_art_group_id)
        }
        next()
      }else{
        console.log("No eres miembro!")
        res.redirect('/logingroup/'+encrypted_art_group_id)
      }
    })
  } 
}

//Pasar los datos del grupo en la request
function GetGroupInfo() {
  return function(req, res, next) {
    let encrypted_id = req.params.id
    let group_id = desencriptar(encrypted_id)

    let consulta = "SELECT * FROM art_groups WHERE id = ?"
    db.query(consulta, [group_id], (err, results) => {
      if (results.length > 0) {
        req.art_group = results[0]
        next()
      } else {
        res.redirect('/notfound')
      }
    })
  } 
}

// Funcion para generar codigo único
function generateUniqueCode(callback) {
  let code = nanoid(8)
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
  })
}

//Convertir todo a minutos para poder comparar dos horas distintas
function ConvertToMinutes(timeStr) {
  let [horas, minutos] = timeStr.split(":").map(Number)
  let total = horas * 60 + minutos
  return total
}

function format_sessions(sessions, currentTime = dayjs().tz("Europe/Madrid")) {
  return sessions.map(s => {
    // Fecha y hora de inicio
    let startDate = dayjs(`${dayjs(s.date_start).format("YYYY-MM-DD")} ${s.hour_start}`, "YYYY-MM-DD HH:mm").tz("Europe/Madrid")
    let has_started = currentTime.isAfter(startDate)

    // Fecha y hora de fin, si existen
    let endDate = null
    let has_ended = false
    let date_end_formatted = null
    let hour_end_formatted = null

    if (s.date_end && s.hour_end) {
      endDate = dayjs(`${dayjs(s.date_end).format("YYYY-MM-DD")} ${s.hour_end}`, "YYYY-MM-DD HH:mm").tz("Europe/Madrid")
      has_ended = currentTime.isAfter(endDate)
      date_end_formatted = endDate.format("YYYY-MM-DD")
      hour_end_formatted = endDate.format("HH:mm")
    }

    return {
      ...s,
      date_start_formatted: startDate.format("YYYY-MM-DD"),
      hour_start_formatted: startDate.format("HH:mm"),
      date_end_formatted,
      hour_end_formatted,
      has_started,
      has_ended
    }
  })
}

//----------------------------MOSTRAR Y SUBIR IMAGENES---------------------------

let sharp = require('sharp')

//Mostrar group picture y banner del grupo, eventos y galería
router.get('/group/:id/image/:image_id',isLoggedIn,isMemberOfGroup(),(req, res) => {
  let filename = req.params.image_id;
  minio.getObject('images', filename, (err, dataStream) => {
    if (err) return res.status(500).send('Error obteniendo imagen');
    res.setHeader('Content-Type', 'image/jpeg');
    dataStream.pipe(res);
  });
});

//Mostrar imagenes subidas por usuarios
router.get('/group/:id/userimage/:image_id',isLoggedIn,isMemberOfGroup(),(req, res) => {
  let filename = req.params.image_id;
  minio.getObject('images', filename, (err, dataStream) => {
    if (err) return res.status(500).send('Error obteniendo imagen');
    res.setHeader('Content-Type', 'image/jpeg');
    dataStream.pipe(res);
  });
});

router.get('/pfp/:pfp_name', (req, res) => {
  let filename = req.params.pfp_name

  minio.getObject('pfp', filename, (err, dataStream) => {
    if (err) {
      console.log('Error obteniendo PFP:', err)
      return res.status(500).send('Error obteniendo foto de perfil')
    }

    res.setHeader('Content-Type', 'image/webp')
    dataStream.pipe(res)
  })
})

function upload_image_minio(bucket, objectName, buffer) {
  return new Promise((resolve, reject) => {
    minio.putObject(bucket, objectName, buffer, (err, etag) => {
      if (err) {
        console.log('ERROR SUBIENDO A MINIO:', err)
        reject(err)
        return
      }
      resolve(etag)
    })
  })
}

// -------------------------- INDISPENSABLES --------------------------




// GET home page
router.get('/', function(req, res, next) {
  let invalidcode = req.query.error === 'invalidcode'
  res.render('inicio',{invalidcode})
})


// GET USER PAGE
router.get('/user/:user_username', isLoggedIn, async (req, res, next) => {
  let find_user = `SELECT id, username, pfp FROM users WHERE username = ?`

  let user_results = await new Promise((resolve, reject) => {
    db.query(find_user, [req.params.user_username], (err, results) => {
      if (err) return reject(err)
      resolve(results)
    })
  })

  if (user_results.length === 0) return res.redirect('/')

  let userData = user_results[0]

  let user = {
    username: userData.username,
    pfp: userData.pfp,
    isyou: userData.id === req.session.myuser.id
  }

  let find_groups = `
    SELECT art_groups.id AS group_id, art_groups.title, art_groups.description, 
    art_groups.group_picture, art_groups.banner, art_groups.code,
    members.type AS member_type
    FROM members
    JOIN art_groups ON members.art_group_id = art_groups.id
    WHERE members.users_id = ?
    ORDER BY members.type DESC
  `

  let group_results = await new Promise((resolve, reject) => {
    db.query(find_groups, [userData.id], (err, results) => {
      if (err) return reject(err)
      resolve(results)
    })
  })

  let groups = group_results.map(r => ({
    encrypted_id: encriptar(r.group_id),
    title: r.title,
    description: r.description,
    type: r.member_type,
    code: r.code,
    group_picture: `/group/${encriptar(r.group_id)}/image/${r.group_picture}`,
    banner: `/group/${encriptar(r.group_id)}/image/${r.banner}`
  }))

  res.render('user', { user, groups })

})

router.post('/changeimg/:username', isLoggedIn, upload.single('new_pfp'), async function(req, res, next) {

  let username = req.params.username
  let pfp_file = req.file

  if (!pfp_file) return res.redirect(`/user/${username}`)

  let pfp_name = "PFP-" + req.session.myuser.myusername + '.webp'

  let sharp = require('sharp')
  let processed_pfp = await sharp(pfp_file.buffer)
    .resize({
      width: 500,
      height: 500,
      fit: sharp.fit.cover,
      position: sharp.strategy.entropy
    })
    .webp({ quality: 80 })
    .toBuffer()

  await upload_image_minio('pfp', pfp_name, processed_pfp)

  let update_sql = "UPDATE users SET pfp = ? WHERE username = ?"
  await new Promise((resolve, reject) => {
    db.query(update_sql, ['/pfp/'+pfp_name, username], (err, result) => {
      if (err) console.log('Error:', err)
      resolve(result)
    })
  })

  req.session.myuser.mypfp = '/pfp/'+pfp_name
  return res.redirect(`/user/${username}`)

})

// -------------------------- LOGIN Y REGISTER -------------------------- 

// GET register 
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
  res.render('register',{message,username,email})

})


// POST register
router.post('/register',  function(req, res, next) {
  let { username, email, password, repeat_password } = req.body

  // Campos vacios
  if (username == "" || email == "" || password == "" || repeat_password == "" ) {
    saveDataRegister(req, username, email)
    res.redirect('/register?error=' + encodeURIComponent(0))
    return 
  }
  //Contraseñas no son iguales
  if (password != repeat_password ){
    saveDataRegister(req, username, email)
    res.redirect('/register?error=' + encodeURIComponent(1))
    return 
  }

  //Excepciones si username o email ya existe en la base de datos
  let consulta_check="SELECT * FROM users WHERE username = ? OR email = ?"

  db.query(consulta_check,[username,email],(error,results)=>{

    let user_already_exists = results.find(u => u.username === username)
    let email_already_exists = results.find(u => u.email === email)
    
    if (user_already_exists){
      saveDataRegister(req, username, email)
      res.redirect('/register?error=' + encodeURIComponent(2))
      return
      
    }else if (email_already_exists){
      saveDataRegister(req, username, email)
      res.redirect('/register?error=' + encodeURIComponent(3))
      return

    }else{ // Ningún error. Proceder al registro y redirección a página principal
      
      bcrypt.genSalt(saltRounds, function(err, salt) {
        bcrypt.hash(password, salt, function(err, hash) {
          
          
          let verify_token = uuidv4()

          let save_token = "INSERT INTO email_verifications (email, token) VALUES (?, ?)"
          // Guardar el token temporalmente
          db.query(save_token, [email, verify_token], function(err2) {

            let consulta_insert = "INSERT INTO users (username,email,password) VALUES (?,?,?)"
          
            db.query(consulta_insert, [username, email, hash], function(err, insertResult) {

              let mailOptions = {
                from: '"Koraw" <Korawinformation@gmail.com>',
                to: email,
                subject: 'Confirma tu cuenta en Koraw',
                html: `
                  <h2>¡Gracias por registrarte en Koraw, ${username}!</h2>
                  <p>Haz clic en el siguiente botón para confirmar tu cuenta:</p>
                  <a href="http://korawapp.duckdns.org:54321/verify?token=${verify_token}" style="padding:10px 15px;background:#228A78;color:white;text-decoration:none;border-radius:4px">Confirmar cuenta</a>
                  <p> Si no eres tú, por favor no haga click en el enlace</p>
                  `
              }

              transporter.sendMail(mailOptions, (error, info) => {
                console.log(error || 'Email enviado: ' + info.response)
              })

              return res.redirect('/login?pleaseverify='+ encodeURIComponent(true))
            })
          }) 
        })
      })
    }
  })
})

function saveDataRegister(req, username, email) {
  req.session.register_username = username || ""
  req.session.register_email = email || ""
}

// GET VERIFY ACCOUNT
router.get('/verify', (req, res) => {
  let token = req.query.token

  //Si no has puesto token
  if (!token) {
    return res.redirect('/')
  }

  // Buscar email asociado al token
  find_token = "SELECT * FROM email_verifications WHERE token = ?"
  db.query(find_token, [token], (err, results) => {

    //Token no valido
    if (results.length === 0) {
      return res.redirect('/')
    }

    let email = results[0].email

    //Marcar usuario como verificado
    let update_verify = "UPDATE users SET verified = true WHERE email = ?"
    db.query(update_verify, [email], (err2) => {

      // ELIMINAR TOKEN DE LA TABLA
      let delete_token = "DELETE FROM email_verifications WHERE token = ?"
      db.query(delete_token, [token])

      res.redirect('/login?completedverify=' + encodeURIComponent(true))
    })
  })
})

/* GET login */
router.get('/login', function(req, res, next) {

  let {error,notverified,completedverify,pleaseverify} = req.query

  res.render('login',{ 
    error: error || "",
    notverified: notverified || "",
    email: req.session.loginEmail || "",
    completedverify: completedverify || "",
    pleaseverify: pleaseverify || ""
  })

  delete req.session.loginEmail

})


// POST LOGIN
router.post('/login', function(req, res, next) {

  let {email, password} = req.body

  let consulta_check="SELECT * FROM users WHERE email = ?"
  db.query(consulta_check, [email], (error,results) => {

    //Existe el email
    if (results.length > 0){
      
      //Check para ver si está verificado
      if (results[0].verified==1){
        console.log("SI ESTÁS VERIFICADO")
        //Hashear la contraseña y compararla con el resultado de la base de datos
        bcrypt.compare(password, results[0].password, (err, correct) => {
          if (correct){
            console.log("Sesión iniciada")
            req.session.myuser= {
              id: results[0].id,
              myusername: results[0].username,
              mypfp: `${results[0].pfp}`,
            }
            res.redirect('/')
            return

          }else{
            req.session.loginEmail = email
            res.redirect('/login?error=' + encodeURIComponent(true))
            return
          }
        })
      }else{
        // No está verificado
        console.log("No estás verificado")
        req.session.loginEmail = email
        res.redirect('/login?notverified=' + encodeURIComponent(false))
        return
      }
      
    }else{
      // No exite el email
      req.session.loginEmail = email
      res.redirect('/login?error=' + encodeURIComponent(true))
      return
    }
  })
})

// CLOSE SESION
router.post('/closesession', isLoggedIn, function(req, res, next) {
  req.session.destroy((err) => {
    // ELIMINAR TAMBIEN COOKIE
    res.clearCookie('connect.sid') 
    res.redirect('/login')
  })
})

// ----------------------------- GESTIÓN DE GRUPO -----------------------------
//Añadir borrar grupos
// GET CREATE GROUP
router.get('/creategroup', isLoggedIn, function(req, res, next) {

  let {error} = req.query

  res.render('create',{
    error: error || "",
  })
})

// POST CREATE GROUP
router.post('/creategroup', isLoggedIn, upload.fields([{ name: 'icon', maxCount: 1 }, { name: 'banner', maxCount: 1 }]), async function(req, res, next) {

  let { title, description, password, repeat_password } = req.body
  let icon = req.files['icon'] ? req.files['icon'][0] : null
  let banner = req.files['banner'] ? req.files['banner'][0] : null

  console.log('FILES:', req.files)
  console.log('ICON BUFFER?', icon && Buffer.isBuffer(icon.buffer))

  // Ambas contraseñas introducidas deben ser iguales
  if (password != repeat_password) return res.redirect('/creategroup?error=' + encodeURIComponent(true))

  //Generar codigo unico para acceder al grupo
  let uniqueCode = await new Promise((resolve, reject) => {
    generateUniqueCode((err, code) => {
      if (err) return res.redirect('/creategroup?error=' + encodeURIComponent(true))
      resolve(code)
    })
  })

  //Nombre default del icono
  let icon_name="default_group_icon.webp"

  //Si has insertado icono, se inserta y renombra
  if (icon){

    icon_name = "Koraw-"+ req.session.myuser.myusername + "-" + Spain.format('YYYY-MM-DD') + '-' + Spain.format('HH-mm-ss') + '-' + (Math.floor(Math.random() * 1000) + 1) + '-group-icon.webp'

    let square_icon = await sharp(icon.buffer)
      .resize({
        width: 500,
        height: 500,
        fit: sharp.fit.cover,
        position: sharp.strategy.entropy 
      })
      .webp({ quality: 80 })
      .toBuffer()

    await upload_image_minio('images', icon_name, square_icon)
  }

  //Nombre default del banner
  let banner_name="default_group_banner.webp"

  //Si has insertado banner, se inserta y renombra
  if (banner){
    banner_name = "Koraw-"+ req.session.myuser.myusername + "-" + Spain.format('YYYY-MM-DD') + '-' + Spain.format('HH-mm-ss') + '-' + (Math.floor(Math.random() * 1000) + 1) + '-group-banner.webp'

    let wide_banner = await sharp(banner.buffer)
      .resize({
        width: 619, // tamaño deseado, ajusta si quieres
        height: 286,
        fit: sharp.fit.cover,
        position: sharp.strategy.entropy // recorta centrando en la parte "interesante"
      })
      .webp({ quality: 80 })
      .toBuffer()

    await upload_image_minio('images',banner_name, wide_banner)
  }

  //Hashear la contraseña
  let hashed_password = await bcrypt.hash(password, saltRounds)

  let consulta_insert = "INSERT INTO art_groups (title, description, group_picture, code, password, banner) VALUES (?, ?, ?, ?, ?, ?)"
  db.query(consulta_insert, [title, description, icon_name, uniqueCode, hashed_password, banner_name], (err, result) => {
    
    //Insertar al miembro que ha creado el grupo en la tabla members y darle acceso super admin
    let new_group_id = result.insertId

    let consulta_insert_member = "INSERT INTO members (users_id,art_group_id,type) VALUES (?, ?, ?)"
    db.query(consulta_insert_member, [req.session.myuser.id,new_group_id,2], (err, member_result) => {
      console.log(err)
      //Redireccionar a la página del grupo
      let encrypted_id = encriptar(new_group_id)
      res.redirect('/group/'+ encrypted_id )

    })
  })
})



// GET ACCESS GROUP
router.get('/accessgroup', isLoggedIn, function(req, res, next) {

  let { code } = req.query

  let consulta_check = "SELECT * FROM art_groups WHERE code = ?"

   db.query(consulta_check, [code], (error,results) => {
    // Intenta encontrar un grupo con el código insertado
    if (results.length>0){

      let encrypted_id =  encriptar(results[0].id)

      // Mira si es un miembro, si lo es le lleva al grupo. Si no lo es, le lleva al login
      let consulta_check_user = "SELECT * FROM members WHERE art_group_id = ? AND users_id = ?"
      db.query(consulta_check_user, [results[0].id,req.session.myuser.id], (error,members_results) => {
        if (members_results.length>0){
          res.redirect('/group/'+ encrypted_id )
          return

        }else{
          req.session.accessgrouptitle = results[0].title
          res.redirect('/logingroup/'+encrypted_id)
          return
        }
      })
      
      //Código invalido
    }else{
      res.redirect('/?error=invalidcode')
    }
   })
})


// GET GROUP
router.get('/group/:id', isLoggedIn, isMemberOfGroup(), GetGroupInfo(), async function(req, res, next) {

  let share = req.query.share === 'true'
  let { created_element } = req.query

  //Display de secciones
  let consulta_check_section = "SELECT * FROM sections WHERE art_group_id = ? ORDER BY date_start"
  let sections = await new Promise((resolve, reject) => {
    db.query(consulta_check_section, [req.art_group.id], (error, sections) => resolve(sections))
  })

  // Mapear cada sección para cambiar icon y banner
  let mapped_sections = sections.map(section => {
    return {
      ...section,
      icon: `/group/${req.params.id}/image/${section.icon}`,
      banner: `/group/${req.params.id}/image/${section.banner}`
    }
  })

  // Nombre de la imagen del grupo que buscará en otro get y pondrá como setheader
  let image_icon = `/group/${req.params.id}/image/${req.art_group.group_picture}`
  let image_banner = `/group/${req.params.id}/image/${req.art_group.banner}`

  res.render('groupsview/group', {
    group: req.art_group,
    sections: mapped_sections,
    encrypted_id: req.params.id,
    isadmin: req.isadmin,
    created_element: created_element || false,
    unique_code: share ? req.art_group.code : false,
    unique_link: share ? `http://korawapp.duckdns.org:54321/group/${req.params.id}` : false,
    image_icon,
    image_banner
  })
})

//GET SHARE LINKS
router.get('/group/:id/getlinks', isLoggedIn, isMemberOfGroup(), function(req, res, next) {
  return res.redirect("/group/"+ req.params.id +"?share="+ encodeURIComponent(true))
})


// GET MEMBERS
router.get('/group/:id/members', isLoggedIn, isMemberOfGroup(), GetGroupInfo(), function(req, res, next) {

  let find_members = "SELECT users.*, members.type FROM members JOIN users ON users.id = members.users_id WHERE members.art_group_id = ? ORDER BY FIELD(members.type, 2, 1, 0)"

  db.query(find_members, [req.art_group.id], (error,users) => {

    let find_superadmin = "SELECT * FROM members WHERE users_id = ?"

    let image_icon = `/group/${req.params.id}/image/${req.art_group.group_picture}`
    let image_banner = `/group/${req.params.id}/image/${req.art_group.banner}`

    db.query(find_superadmin, [req.session.myuser.id], (error,current_user) => {
      res.render("groupsview/members", {
        encrypted_id: req.params.id,
        isadmin: req.isadmin,
        issuperadmin: (current_user[0].type == 2),
        members: users,
        image_icon,
        image_banner,
        group_title: req.art_group.title
      })
    })
  })
})


// POST MEMBERS MAKE OR REMOVE ADMIN
router.post('/group/:id/members/:changeadmin_id', isLoggedIn, isMemberOfGroup(true), GetGroupInfo(), function(req, res, next) {

  let find_superadmin = "SELECT * FROM members WHERE users_id = ?"

  db.query(find_superadmin, [req.session.myuser.id], (error,mysuperadmin) => {
    //El usuario que ha mandado la acción existe
    if (mysuperadmin.length >0){
      //El usuario que ha mandado la acción es el creador. El unico que puede cambiar admin
      if (mysuperadmin[0].type !== "2"){

        let find_changeadmin = "SELECT * FROM members WHERE users_id = ? AND art_group_id = ?"

        db.query(find_changeadmin, [req.params.changeadmin_id,req.art_group.id], (error,user) => {

          //El usuario que vamos a cambiar existe y no es el creador
          if (user==undefined || user.length <=0 || user[0].type== "2"){
            return res.redirect("/group/"+ req.params.id +"/members")
          }

          //Si es admin, no lo será. Si no es admin, lo será.
          let newtype = user[0].type === 1 ? 0 : 1

          let changeadmin = "UPDATE members SET type = ? WHERE users_id = ? AND art_group_id = ?"

          //Cambiar o quitar admin
          db.query(changeadmin, [newtype,req.params.changeadmin_id,req.art_group.id], (error,changed_user) => {
            return res.redirect("/group/"+ req.params.id +"/members")
          })
        })

      }else{
        return res.redirect("/group/"+ req.params.id +"/members")
      }
    }else{
      return res.redirect("/group/"+ req.params.id +"/members")
    }
  })
})


// ----------------------------- LOGIN & REGISTER MEMBER TO GROUP -----------------------------

// GET LOGIN GROUP
router.get('/logingroup/:id', isLoggedIn, function(req, res, next) {

  let title = req.session.accessgrouptitle
  delete req.session.accessgrouptitle

  //Si la contraseña da error lo muestra
  let { error } = req.query || false

  console.log("titulo:",title)
  if (title == "" || title ==undefined){
    let consulta_check = "SELECT * FROM art_groups WHERE id = ?"
    db.query(consulta_check, [desencriptar(req.params.id)], (error,results) => {
      console.log("entro titulo:",results[0].title,)
      res.render('login_group',{title:results[0].title, error })
    })
  }else{
    res.render('login_group',{title, error })
  }
  
})


// POST LOGIN GROUP
router.post('/logingroup/:id', isLoggedIn, function(req, res, next) {
  let {password,group_title} = req.body
  let encrypted_id = req.params.id
  let id = desencriptar(encrypted_id)

  let consulta_check = "SELECT * FROM art_groups WHERE id = ?"
  db.query(consulta_check, [id], (error,results) => {
    //Si la contraseña es correcta te envia al grupo, si no te da error
    bcrypt.compare(password, results[0].password, (err, correct) => {

      if(correct){
        // Si no eres miembro te añade a la base de datos
        let consulta_check_user = "SELECT * FROM members WHERE art_group_id = ? AND users_id = ?"
        db.query(consulta_check_user, [id,req.session.myuser.id], (error,results) => {

          if (results.length == 0){
            console.log("Te vamos a añadir por que no eres miembro")
            db.query("INSERT INTO members (users_id, art_group_id) VALUES (?, ?)", [req.session.myuser.id, id])
          }else{
            console.log("ya existes,",results)
          }
          res.redirect('/group/'+ encrypted_id )

        })
        
      }else{
        req.session.accessgrouptitle = group_title
        res.redirect('/logingroup/'+ encrypted_id +'?error='+encodeURIComponent(true))
      }
    })
  })
})


// ----------------------------- CREATE EVENT AND GALLERY -----------------------------
// GET CREATE ELEMENT
router.get('/group/:id/newelement', isLoggedIn, isMemberOfGroup(true), GetGroupInfo(), function(req, res, next) {
  
  let {error} = req.query

  // Nombre de la imagen del grupo que buscará en otro get y pondrá como setheader
  let image_icon = `/group/${req.params.id}/image/${req.art_group.group_picture}`
  let image_banner = `/group/${req.params.id}/image/${req.art_group.banner}`

  res.render('groupsview/newelement',{
    error: error || false,
    group_title: req.art_group.id,
    image_icon,
    image_banner,
    encrypted_id: req.params.id,
    group_title: req.art_group.title

  })
})

//POST CREATE ELEMENT
router.post('/group/:id/newelement', isLoggedIn, isMemberOfGroup(true), GetGroupInfo(), upload.fields([{ name: 'icon' }, { name: 'banner' }]), async function(req, res, next) {

  let {title, description, section_type} = req.body

  let icon = req.files['icon'] ? req.files['icon'][0] : null
  let banner = req.files['banner'] ? req.files['banner'][0] : null

   // Check de que el titulo NO esté vacio
  if (!title) {
    res.redirect('/group/' + req.params.id + '/newelement?error=' + encodeURIComponent(1))
    return
  }

  let ended = null

  // Check de que hayas escogido galería o evento. Si es evento, el ended se pone en 0 (false)
  if (section_type !== "gallery" && section_type !== "event") {
    res.redirect('/group/' + req.params.id + '/newelement?error=' + encodeURIComponent(2))
    return
  } else if (section_type == "event") {
    ended = 0
  }

  // Buscar que ese titulo no exita ya en el grupo
  let check_same_section_name = "SELECT * FROM sections WHERE title = ? and art_group_id = ?"
  let results = await new Promise((resolve, reject) => {
    db.query(check_same_section_name, [title, req.art_group.id], (error, results) => {
      if (error) reject(error)
      else resolve(results)
    })
  })

  if (results.length > 0) {
    res.redirect('/group/' + req.params.id + '/newelement?error=' + encodeURIComponent(3))
    return
  }

  //Nombre default del icono
  let icon_name
  let banner_name
  //Nombre default del banner
  if (section_type == "gallery") {
    banner_name="default_gallery_banner.webp"
    icon_name="default_gallery_icon.webp"
  } else if (section_type == "event") {
    banner_name="default_event_banner.webp"
    icon_name="default_event_icon.webp"
  }

  //Si has insertado icono, se inserta y renombra
  if (icon){

    icon_name = "Koraw-"+ req.session.myuser.myusername + "-" + Spain.format('YYYY-MM-DD') + '-' + Spain.format('HH-mm-ss') + '-' + (Math.floor(Math.random() * 1000) + 1) + '-' +section_type +'-icon.webp'

    let square_icon = await sharp(icon.buffer)
      .resize({
        width: 500, 
        height: 500,
        fit: sharp.fit.cover,
        position: sharp.strategy.entropy 
      })
      .webp({ quality: 80 })
      .toBuffer()

    await upload_image_minio('images', icon_name, square_icon)
  }

  //Si has insertado banner, se inserta y renombra
  if (banner){
    banner_name = "Koraw-"+ req.session.myuser.myusername + "-" + Spain.format('YYYY-MM-DD') + '-' + Spain.format('HH-mm-ss') + '-'+ (Math.floor(Math.random() * 1000) + 1) + '-' +section_type + '-banner.webp'

    let wide_banner = await sharp(banner.buffer)
      .resize({
        width: 500, 
        height: 500,
        fit: sharp.fit.cover,
        position: sharp.strategy.entropy 
      })
      .webp({ quality: 80 })
      .toBuffer()

    await upload_image_minio('images',banner_name, wide_banner)
  }


  //Insertar a sección si todo ha ido bien
  let insert_section = "INSERT INTO sections (section_type, title, description, icon, banner, art_group_id, ended) VALUES (?,?,?,?,?,?,?)"
  await new Promise((resolve, reject) => {
    db.query(insert_section, [section_type, title, description, icon_name, banner_name, req.art_group.id, ended], (error, results) => {
      if (error) reject(error)
      else resolve(results)
    })
  })

  // Redirect con mensaje de success diferente para un grupo o galería
  if (section_type == "gallery") {
    res.redirect('/group/' + req.params.id + '?created_element=' + encodeURIComponent(1))
  } else if (section_type == "event") {
    res.redirect('/group/' + req.params.id + '?created_element=' + encodeURIComponent(2))
  }
})

// ----------------------------- ACCESS EVENT OR GALLERY -----------------------------

// GET VISTA GALERÍA
router.get('/group/:id/gallery/:sect_id', isLoggedIn, isMemberOfGroup(), GetGroupInfo(), async function(req, res, next) {

  let find_section = "SELECT * FROM sections WHERE id = ?"

  let gallery_results = await new Promise((resolve, reject) => {
    db.query(find_section, [req.params.sect_id], (error,gallery_results) => {
      if (error) reject(error)
      else resolve(gallery_results) 
    })
  })

  //Que exista la galería y que sea de tipo galería
  if(gallery_results == null || gallery_results== undefined || gallery_results.length == 0 || gallery_results[0].section_type!=="gallery"){
    res.redirect('/group/'+ req.params.id)
  }
  

  //Buscar todas las imagenes que ha subido el usuario, siempre y cuando no sean la misma imagen subida a diferentes sesiones. Ordenadas por fecha
  let find_user_uploaded_images = "SELECT user_images.* FROM user_images user_images INNER JOIN (SELECT image_name, MAX(uploaded_at) as max_uploaded FROM user_images WHERE user_id = ? GROUP BY image_name) grouped_ui ON user_images.image_name = grouped_ui.image_name AND user_images.uploaded_at = grouped_ui.max_uploaded AND user_images.user_id = ? ORDER BY user_images.uploaded_at DESC"

  let user_uploaded_imgs = await new Promise((resolve, reject) => {
    db.query(find_user_uploaded_images, [req.session.myuser.id, req.session.myuser.id], (error, results) => resolve(results))
  })

  
  let formatted_user_uploaded_imgs = user_uploaded_imgs.map(images => {
    return {
      ...images,
      image_name: `/group/${req.params.id}/userimage/${images.image_name}`,
    }
  })


  let find_gallery_images = "SELECT user_images.*, u.pfp as user_pfp, u.username as uploader_name FROM user_images user_images JOIN users u ON user_images.user_id = u.id WHERE user_images.group_id = ? AND gallery_id = ? ORDER BY user_images.uploaded_at ASC"

  let gallery_images = await new Promise((resolve, reject) => {
    db.query(find_gallery_images, [req.art_group.id,req.params.sect_id], (error,gallery_images) => {
      if (error) reject(error)
      else resolve(gallery_images) 
    })
  })

  console.log("Imagenes DE LA GALERIA",gallery_images)


  let formatted_gallery_images = gallery_images.map(images => {
    dayjs(images.uploaded_at).tz('Europe/Madrid')
    let date = dayjs(images.uploaded_at).tz('Europe/Madrid').format('DD/MM/YYYY')
    let hour = dayjs(images.uploaded_at).tz('Europe/Madrid').format('HH:mm')

    let { uploaded_at, ...rest } = images
    return {
      ...rest,
      date: date,
      hour: hour,
      image_name: `/group/${req.params.id}/userimage/${images.image_name}`,
      is_you: images.user_id === req.session.myuser.id 
    }
  })

  let form_action=`/group/${req.params.id}/gallery/${req.params.sect_id}/gallery_uploadimg`
  let form_action_edit= `/group/${req.params.id}/gallery/${req.params.sect_id}/editimg`
  let form_action_delete= `/group/${req.params.id}/gallery/${req.params.sect_id}/deleteimg`

  res.render('groupsview/gallery',{
    form_action,
    form_action_edit,
    form_action_delete,
    gallery: gallery_results[0],
    gallery_icon: `/group/${req.params.id}/image/${gallery_results[0].icon}`,
    gallery_banner:`/group/${req.params.id}/image/${gallery_results[0].banner}`,
    gallery_images: formatted_gallery_images,
    user_uploaded_imgs:formatted_user_uploaded_imgs
  })
})


// GET VISTA EVENT
router.get('/group/:id/event/:sect_id', isLoggedIn, isMemberOfGroup(), GetGroupInfo(), async function(req, res, next) {

  // Miramos que exista el evento
  let find_section = "SELECT * FROM sections WHERE id = ?"
  let event = await new Promise((resolve, reject) => {
    db.query(find_section, [req.params.sect_id], (error, results) => resolve(results))
  })

  //Si existe, continuamos
  if(event.length > 0) {

    // Mapear para cambiar icon y banner
    let mapped_event = event.map(e => {
      return {
        ...e,
        icon: `/group/${req.params.id}/image/${e.icon}`,
        banner: `/group/${req.params.id}/image/${e.banner}`
      }
    })

    //Buscamos todas las sesiones del evento
    let find_sessions = "SELECT * FROM sessions WHERE section_id = ? ORDER BY date_start ASC, hour_start ASC"
    let sessions = await new Promise((resolve, reject) => {
      db.query(find_sessions, [event[0].id], (error, sessions) => resolve(sessions))
    })

    //Formatear la session para añadir variables de has started, has ended o active
    let formatted_sessions = format_sessions(sessions)

    res.render('groupsview/event', {
      encrypted_id: req.params.id,
      event_id: req.params.sect_id,
      isadmin: req.isadmin,
      event: mapped_event[0],
      sessions: formatted_sessions
    })

  } else {
    console.log("fallado primero")
    res.redirect('/group/' + req.params.id)
  }
})
// ----------------------------- UPLOAD TO GALLERY  -----------------------------

// POST UPLOAD TO GALLERY
router.post('/group/:id/gallery/:sect_id/gallery_uploadimg', isLoggedIn, isMemberOfGroup(), GetGroupInfo(), upload.single('image'), async function(req, res, next) {

  let description = req.body.description
  let already_uploaded_image = req.body.already_uploaded_image
  let new_image = req.file 

  // Si hay archivo subido Y foto seleccionada, error
  if (new_image && already_uploaded_image) {
    return res.redirect(`/group/${req.params.id}/gallery/${req.params.sect_id}?error=1`)
  }

  // Si la descripcion es mayor de 2000
  if (description && description.length > 2000) {
    console.log("DESCRIPTION------------------------------------------")
    return res.redirect(`/group/${req.params.id}/gallery/${req.params.sect_id}`)
  }

  // Si seleccionó imagen ya subida
  if (already_uploaded_image && !new_image) {

    let find_image_in_same_session = "SELECT * FROM user_images WHERE user_id = ? AND image_name = ? AND group_id = ? AND gallery_id = ? "

    let found_same_img=await new Promise((resolve, reject) => {
      db.query(find_image_in_same_session, [req.session.myuser.id,already_uploaded_image,req.art_group.id,req.params.sect_id], (err, result) => resolve(result))
    })

    if(found_same_img.length > 0){
      console.log("Esa ya la has subido a esta sesión!")
      return res.redirect(`/group/${req.params.id}/gallery/${req.params.sect_id}`)
    }

    let insert_sql = "INSERT INTO user_images (user_id, image_name, group_id, gallery_id,description) VALUES (?, ?, ?, ?, ?) "
    await new Promise((resolve, reject) => {
      db.query(insert_sql, [req.session.myuser.id,already_uploaded_image,req.art_group.id,req.params.sect_id, description], (err, result) => resolve(result))
    })

    return res.redirect(`/group/${req.params.id}/gallery/${req.params.sect_id}`)
  }

  // Si subió imagen nueva
  if (new_image && !already_uploaded_image) {
    // Contar cuántas imágenes tiene este user
    let count_sql = "SELECT COUNT(*) AS count FROM user_images WHERE user_id = ?"
    let count_result = await new Promise((resolve, reject) => {
      db.query(count_sql, [req.session.myuser.id], (err, result) => resolve(result))
    })

    let addingnumber = count_result[0].count + 1

    //Nombre imposible de replicar
    let final_name = `Koraw-${req.session.myuser.myusername}-${Spain.format('YYYY-MM-DD')}-${Spain.format('HH-mm-ss')}-${Math.floor(Math.random() * 1000) + 1 + addingnumber}-uploaded-image.webp`

    
    // Subir a MinIO
    await minio.putObject('images', final_name, new_image.buffer)

    // Insertar nombre de imagenes y keys en BD
    let insert_sql = "INSERT INTO user_images (user_id, image_name, group_id, gallery_id, description)VALUES (?, ?, ?, ?, ?)"
    await new Promise((resolve, reject) => {
      db.query(insert_sql, [req.session.myuser.id,final_name,req.art_group.id,req.params.sect_id, description], (err, result) => resolve(result))
    })

    return res.redirect(`/group/${req.params.id}/gallery/${req.params.sect_id}`)
  }

  // Si no hizo nada, redirigir igual
  return res.redirect(`/group/${req.params.id}/gallery/${req.params.sect_id}`)


  
})



// ACTUALIZAR DESCRIPCION IMAGE OF GALLERY
router.post('/group/:id/gallery/:sect_id/editimg/:image_id', isLoggedIn, isMemberOfGroup(), GetGroupInfo(), async function(req, res, next) {

  let img_id = req.params.image_id
  let new_desc = req.body.description

  if (new_desc.length > 2000) {
    return res.redirect('/group/'+ req.params.id + '/gallery/' + req.params.sect_id)
  }

  let find_image = "SELECT * FROM user_images WHERE id = ?"

  let found_img = await new Promise((resolve, reject) => {
    db.query(find_image, [img_id], (err, result) => resolve(result))
  })

  if (found_img.length === 0) {
    return res.redirect('/group/'+ req.params.id + '/gallery/' + req.params.sect_id)
  }

  if (found_img[0].user_id !== req.session.myuser.id) {
    return res.redirect('/group/'+ req.params.id + '/gallery/' + req.params.sect_id)
  }

  let update_desc = "UPDATE user_images SET description = ? WHERE id = ?"
  await new Promise((resolve, reject) => {
    db.query(update_desc, [new_desc, img_id], (err, result) => resolve(result))
  })

  return res.redirect('/group/'+ req.params.id + '/gallery/' + req.params.sect_id)

})

// DELETE IMAGE SECTION EVENT
router.post('/group/:id/gallery/:sect_id/deleteimg/:image_id', isLoggedIn, isMemberOfGroup(), GetGroupInfo(), async function(req, res, next) {

  let img_id = req.params.image_id

  let find_image = "SELECT * FROM user_images WHERE id = ?"

  let found_img = await new Promise((resolve, reject) => {
    db.query(find_image, [img_id], (err, result) => resolve(result))
  })

  if (found_img.length === 0) {
    return res.redirect('/group/'+ req.params.id + '/gallery/' + req.params.sect_id)
  }

  if (found_img[0].user_id !== req.session.myuser.id) {
    return res.redirect('/group/'+ req.params.id + '/gallery/' + req.params.sect_id)
  }

  let delete_img = "DELETE FROM user_images WHERE id = ?"
  await new Promise((resolve, reject) => {
    db.query(delete_img, [img_id], (err, result) => resolve(result))
  })

  return res.redirect('/group/'+ req.params.id + '/gallery/' + req.params.sect_id)
})



// ----------------------------- SESSIONS IN EVENT  -----------------------------

// GET CREATE SESSION IN EVENT
router.get('/group/:id/event/:sect_id/newsession', isLoggedIn, isMemberOfGroup(true), GetGroupInfo(), function(req, res, next) {

  let {error} = req.query

  // Nombre de la imagen del grupo que buscará en otro get y pondrá como setheader
  let image_icon = `/group/${req.params.id}/image/${req.art_group.group_picture}`
  let image_banner = `/group/${req.params.id}/image/${req.art_group.banner}`

  res.render('groupsview/newsession',{
    encrypted_id: req.params.id,
    event_id: req.params.sect_id,
    error: error || false,
    group_title: req.art_group.title,
    image_icon,
    image_banner,
    group_title: req.art_group.title
  })

})


// POST CREATE SESSION IN EVENT
router.post('/group/:id/event/:sect_id/newsession', isLoggedIn, isMemberOfGroup(true), GetGroupInfo(), function(req, res, next) {

  let { 
    topic, description, 
    start_date_option, date_start, end_date_option, date_end, 
    start_hour_option, hour_start, end_hour_option, hour_end, 
    max_images_option, images_custom_count } = req.body || null

  
  //-----Validación de seguridad-----

  let validStartDateOptions = ["now", "custom"]
  let validStartHourOptions = ["start", "custom"]
  let validEndDateOptions = ["none", "custom"]
  let validEndHourOptions = ["midnight", "custom"]
  let validMaxImagesOptions = ["one", "unlimited", "custom"]

  if (
    !validStartDateOptions.includes(start_date_option) ||
    !validStartHourOptions.includes(start_hour_option) ||
    !validEndDateOptions.includes(end_date_option) ||
    !validEndHourOptions.includes(end_hour_option) ||
    !validMaxImagesOptions.includes(max_images_option)
  ) {
    return res.status(400).send("Opción inválida detectada")
  }

    // Validar campos obligatorios del tema
  if (!topic || topic.length > 30 || description.length > 250) {
    return res.status(400).send("Tema o descripción inválida")
  }

  //Mirar si descripción es vacio. Si está vacio, es null
  let isOnlySpace = str => !str.replace(/\s/g, '').length
  if(isOnlySpace(description)){ description = null}


  //Check de si es hora correcta
  let isValidHour = (value) => /^([01]\d|2[0-3]):([0-5]\d)$/.test(value)
  
  // Si has elegido custom te las formatea en forma de fecha
  if (start_date_option == "custom"){

    date_start = new Date(date_start)

    //Miramos que la fecha sea válida. No lo es si ha elegido custom, pero no ha insertado fecha
    if (isNaN(date_start.getTime())){
      return res.redirect("/group/"+req.params.id+"/event/"+req.params.sect_id+"/newsession?error=5")
    }
    // Si la hora no es custom, te pone el principio del dia
    if (start_hour_option!=="custom"){
      hour_start = "00:00"
    // Si la hora es custom y la hora no es valida, te da error
    }else if (start_hour_option=="custom" && !isValidHour(hour_start) ){
      return res.redirect("/group/"+req.params.id+"/event/"+req.params.sect_id+"/newsession?error=4")
    //Si la hora es custom y la hora es valida, te hace una
    }

  } else {
    date_start =  Spain.format('YYYY-MM-DD')
    start_hour_option = null
    hour_start = Spain.format('HH:mm')
  }

  // Hacemos lo mismo para la date_end
  if (end_date_option == "custom"){
    date_end = new Date(date_end)
    if (isNaN(date_end.getTime())){
      return res.redirect("/group/"+req.params.id+"/event/"+req.params.sect_id+"/newsession?error=5")
    }
    if (end_hour_option!=="custom"){
      hour_end = "23:59"

    }else if (end_hour_option=="custom" && !isValidHour(hour_end)){
      return res.redirect("/group/"+req.params.id+"/event/"+req.params.sect_id+"/newsession?error=4")
    }

  }else{
    date_end = null
    end_hour_option = null
    hour_end = null
  }
  // --------------------------------------------

  //Si ambas fechas son custom, mira que el start no sea mayor
  // Y si son iguales, mira que la hora start no sea mayor
  if (start_date_option == "custom" && end_date_option == "custom") {

    if (date_start > date_end) {
      return res.redirect("/group/"+req.params.id+"/event/"+req.params.sect_id+"/newsession?error=1")
    }

    if (date_start.toDateString() == date_end.toDateString()) {
      if (start_hour_option == "custom" && end_hour_option == "custom" && ConvertToMinutes(hour_start) >= ConvertToMinutes(hour_end)) {
        return res.redirect("/group/"+req.params.id+"/event/"+req.params.sect_id+"/newsession?error=2")
      }
    }
  }


  //Si opción de imagenes es one pone 1, si es unlimited null y si no, el valor custom
  let final_max_images = max_images_option === "one" ? 1 : max_images_option === "unlimited" ? null : images_custom_count


  //Mira que no haya otra sesión con el mismo titulo
  let check_same_title = "SELECT * FROM sessions WHERE section_id = ? AND topic = ?"
  console.log("sect id:",req.params.sect_id)
  db.query(check_same_title, [req.params.sect_id,topic], (error,results) => {
    console.log("resultado:",results)
    console.log("error:",error)
    if (results.length>0){
      return res.redirect("/group/"+req.params.id+"/event/"+req.params.sect_id+"/newsession?error=3")
    }else{
      console.log(
      "TITULO:",topic, 
      "\n DESCRIPCIÓN:",description, 
      "\n START DATES:", start_date_option, date_start, 
      "\n START HOURS:", start_hour_option, hour_start,
      "\n END DATES: ",end_date_option, date_end, 
      "\n END HOURS: ",end_hour_option, hour_end, 
      "\n IMAGENES:", max_images_option, images_custom_count)

      
      //Insertar si todo es correcto y válido
      let insert_session = "INSERT INTO sessions (topic, description, date_start, date_end, section_id, images_per_user, hour_start, hour_end) VALUES (?,?,?,?,?,?,?,?)"

      db.query(insert_session, [topic,description,date_start,date_end,req.params.sect_id,final_max_images,hour_start,hour_end], (error,insert_results) => {
        if (error){ console.log(error)}
        console.log(insert_results)
        res.redirect("/group/"+req.params.id+"/event/"+req.params.sect_id)
      })
    }
  })  
})

// GET SESSION OF EVENT
router.get('/group/:id/event/:sect_id/session/:sess_id', isLoggedIn, isMemberOfGroup(), GetGroupInfo(), async function(req, res, next) {
  
  

  //Buscar todas las imagenes subidas a la sesión
  let find_section = "SELECT * FROM sections WHERE id = ?"

  let section_result = await new Promise((resolve, reject) => {
    db.query(find_section, [req.params.sect_id], (error, section_results) => 
    {
      if (error) reject(error)
      else resolve(section_results)
    })
  })

  let find_session = "SELECT * FROM sessions WHERE id = ?"

  let sess_result = await new Promise((resolve, reject) => {
    db.query(find_session, [req.params.sess_id], (error, results) => resolve(results))
  })


  //Si la sesion existe, adelante
  if (sess_result.length > 0 || section_result.length>0) {

    let formatted_session = format_sessions(sess_result)

    // Si la sesion no ha empezado, te redirije
    if (formatted_session[0].has_started == false) {
      res.redirect("/group/" + req.params.id + "/event/" + req.params.sect_id)
    } else {
      
      //Buscar todas las imagenes que ha subido el usuario, siempre y cuando no sean la misma imagen subida a diferentes sesiones. Ordenadas por fecha
      let find_user_uploaded_images = "SELECT user_images.* FROM user_images user_images INNER JOIN (SELECT image_name, MAX(uploaded_at) as max_uploaded FROM user_images WHERE user_id = ? GROUP BY image_name) grouped_ui ON user_images.image_name = grouped_ui.image_name AND user_images.uploaded_at = grouped_ui.max_uploaded AND user_images.user_id = ? ORDER BY user_images.uploaded_at DESC"
    
      let user_uploaded_imgs = await new Promise((resolve, reject) => {
        db.query(find_user_uploaded_images, [req.session.myuser.id, req.session.myuser.id], (error, results) => resolve(results))
      })

      
      let formatted_user_uploaded_imgs = user_uploaded_imgs.map(images => {
        return {
          ...images,
          image_name: `/group/${req.params.id}/userimage/${images.image_name}`,
        }
      })

      //Buscar todas las imagenes subidas a la sesión
      let find_session_images = "SELECT user_images.*, u.pfp as user_pfp, u.username as uploader_name FROM user_images user_images JOIN users u ON user_images.user_id = u.id WHERE user_images.group_id = ? AND user_images.session_id = ? ORDER BY user_images.uploaded_at ASC"
    
      let session_images = await new Promise((resolve, reject) => {
        db.query(find_session_images, [req.art_group.id,req.params.sess_id], (error, results) => 
        {
          if (error) reject(error)
          else resolve(results)
        })
      })

      console.log(session_images)

      let formatted_session_images = session_images.map(images => {
        dayjs(images.uploaded_at).tz('Europe/Madrid')
        let date = dayjs(images.uploaded_at).tz('Europe/Madrid').format('DD/MM/YYYY')
        let hour = dayjs(images.uploaded_at).tz('Europe/Madrid').format('HH:mm')

        let { uploaded_at, ...rest } = images
        return {
          ...rest,
          date: date,
          hour: hour,
          image_name: `/group/${req.params.id}/userimage/${images.image_name}`,
          is_you: images.user_id === req.session.myuser.id 
        }
      })


      let section_icon = section_result[0].icon
      section_icon = `/group/${req.params.id}/image/${section_icon}`

      let form_action= `/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}/uploadimg`
      let form_action_edit= `/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}/editimg`
      let form_action_delete= `/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}/deleteimg`

      res.render('groupsview/session', {
        form_action,
        form_action_edit,
        form_action_delete,
        session: formatted_session[0],
        user_uploaded_imgs: formatted_user_uploaded_imgs,
        session_images: formatted_session_images,
        section_icon: section_icon

      })
    }

  } else {
    res.redirect("/group/" + req.params.id + "/event/" + req.params.sect_id)
  }
})

// POST UPLOAD IMAGE ON SESSION
router.post('/group/:id/event/:sect_id/session/:sess_id/uploadimg', isLoggedIn, isMemberOfGroup(), GetGroupInfo(), upload.single('image'), async function(req, res, next) {
  let description = req.body.description
  let already_uploaded_image = req.body.already_uploaded_image
  let new_image = req.file 

  // Si hay archivo subido Y foto seleccionada, error
  if (new_image && already_uploaded_image ) {
    console.log("-------------------ambbbaass------------------------")
    return res.redirect(`/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}?error=1`)
  }

  //Si la descripción es de mas de 2000 caracteres
  if (description && description.length > 2000) {
    console.log("DESCRIPTION------------------------------------------")
    return res.redirect(`/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}`)
  }

  // Si seleccionó imagen ya subida
  if (already_uploaded_image && !new_image) {

    let find_image_in_same_session = "SELECT * FROM user_images WHERE user_id = ? AND image_name = ? AND group_id = ? AND session_id = ? "

    let found_same_img=await new Promise((resolve, reject) => {
      db.query(find_image_in_same_session, [req.session.myuser.id,already_uploaded_image,req.art_group.id,req.params.sess_id], (err, result) => resolve(result))
    })

    if(found_same_img.length > 0){
      console.log("--------------Esa ya la has subido a esta sesión!---------------")
       return res.redirect(`/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}`)
    }

    let insert_sql = "INSERT INTO user_images (user_id, image_name, group_id, session_id, description)VALUES (?, ?, ?, ?, ?)"
    await new Promise((resolve, reject) => {
      db.query(insert_sql, [req.session.myuser.id,already_uploaded_image,req.art_group.id,req.params.sess_id, description], (err, result) => resolve(result))
    })

    console.log("--------sialFINAL-------------------------")
    return res.redirect(`/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}`)
  }

  // Si subió imagen nueva
  if (new_image && !already_uploaded_image) {
    // Contar cuántas imágenes tiene este user
    let count_sql = "SELECT COUNT(*) AS count FROM user_images WHERE user_id = ?"
    let count_result = await new Promise((resolve, reject) => {
      db.query(count_sql, [req.session.myuser.id], (err, result) => resolve(result))
    })

    let addingnumber = count_result[0].count + 1

    //Nombre imposible de replicar
    let final_name = `Koraw-${req.session.myuser.myusername}-${Spain.format('YYYY-MM-DD')}-${Spain.format('HH-mm-ss')}-${Math.floor(Math.random() * 1000) + 1 + addingnumber}-uploaded-image.webp`

    // Subir a MinIO
    await minio.putObject('images', final_name, new_image.buffer)

    // Insertar nombre de imagenes y keys en BD
    let insert_sql = "INSERT INTO user_images (user_id, image_name, group_id, session_id, description)VALUES (?, ?, ?, ?, ?)"
    await new Promise((resolve, reject) => {
      db.query(insert_sql, [req.session.myuser.id, final_name, req.art_group.id, req.params.sess_id, description], (err, result) => {
        console.log("QUE HA PASADO -------------------------", result, err)
        if (err) return reject(err)
        resolve(result)
      })
    })

    console.log("SI AL FINAL NUEVAAAAAAAAA--------------------------------------------------------")
    return res.redirect(`/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}`)
  }

  // Si no hizo nada, redirigir igual
  console.log("NADDDDDAAAAAAAAAAAAA-----------------------------------------")
  return res.redirect(`/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}`)
})


// ACTUALIZAR DESCRIPCION IMAGE OF EVENT
router.post('/group/:id/event/:sect_id/session/:sess_id/editimg/:image_id', isLoggedIn, isMemberOfGroup(), GetGroupInfo(), async function(req, res, next) {

  let img_id = req.params.image_id
  let new_desc = req.body.description

  if (new_desc.length > 2000) {
    return res.redirect(`/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}`)
  }

  let find_image = "SELECT * FROM user_images WHERE id = ?"

  let found_img = await new Promise((resolve, reject) => {
    db.query(find_image, [img_id], (err, result) => resolve(result))
  })

  if (found_img.length === 0) {
    return res.redirect(`/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}`)
  }

  if (found_img[0].user_id !== req.session.myuser.id) {
    return res.redirect(`/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}`)
  }

  let update_desc = "UPDATE user_images SET description = ? WHERE id = ?"
  await new Promise((resolve, reject) => {
    db.query(update_desc, [new_desc, img_id], (err, result) => resolve(result))
  })

  return res.redirect(`/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}`)

})

// DELETE IMAGE SECTION EVENT
router.post('/group/:id/event/:sect_id/session/:sess_id/deleteimg/:image_id', isLoggedIn, isMemberOfGroup(), GetGroupInfo(), async function(req, res, next) {

  let img_id = req.params.image_id

  let find_image = "SELECT * FROM user_images WHERE id = ?"

  let found_img = await new Promise((resolve, reject) => {
    db.query(find_image, [img_id], (err, result) => resolve(result))
  })

  if (found_img.length === 0) {
    return res.redirect(`/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}`)
  }

  if (found_img[0].user_id !== req.session.myuser.id) {
    return res.redirect(`/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}`)
  }

  let delete_img = "DELETE FROM user_images WHERE id = ?"
  await new Promise((resolve, reject) => {
    db.query(delete_img, [img_id], (err, result) => resolve(result))
  })

  return res.redirect(`/group/${req.params.id}/event/${req.params.sect_id}/session/${req.params.sess_id}`)
})






module.exports = router;




//enviar gmail
//servidor de imagenes
//imagenes a nivel de usuario en tu perfil
//cambiar tu foto de perfil
//cambiar fotos y banners de secciones y grupos
//Comentarios, a nivel de la imagen a nivel de usuario

// let find_images = "SELECT * FROM sessions WHERE id = ?"

// let uploaded_images = await new Promise((resolve, reject) => {
//   db.query(find_images, [], (error, results) => resolve(results))
// })