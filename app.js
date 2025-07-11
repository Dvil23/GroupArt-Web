var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var indexRouter = require('./routes/index');
// var usersRouter = require('./routes/users');

var app = express();

// view engine setup SOLO SI TENGO JADE
// app.set('views', path.join(__dirname, 'views'));
// app.set('view engine', 'jade');

// ejs
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.locals.dayjs = require("dayjs");

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// libreria session y su configuración
const session = require('express-session')
app.use(session({
  secret: process.env.SESSION_COOKIE,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 días en milisegundos
  }
}));

app.use('/sweetalert2', express.static('node_modules/sweetalert2/dist'));

app.use('/', indexRouter);
// app.use('/users', usersRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  res.status(err.status || 500);
  res.send({
    error: true,
    message: err.message,
  });
});

module.exports = app;
