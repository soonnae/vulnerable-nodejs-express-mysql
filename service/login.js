/*

    Reference: https://codeshack.io/basic-login-system-nodejs-express-mysql/

*/

var mysql = require("mysql");
var express = require("express");
var session = require("express-session");
var bodyParser = require("body-parser");
var path = require("path");
var csrf = require("csurf");
var rateLimit = require("express-rate-limit");

var connection = mysql.createConnection({
  host: "db",
  user: "login",
  password: "login",
  database: "login",
});

var app = express();
app.use(
  session({
    secret: require("crypto").randomBytes(64).toString("hex"),
    resave: true,
    saveUninitialized: true,
    cookie: { secure: true } // 쿠키에 secure 플래그 추가
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// CSRF 보호 미들웨어 추가
var csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// 속도 제한 미들웨어 추가
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 100 // 각 IP당 100개의 요청으로 제한
});
app.use(limiter);

app.get("/", function (request, response) {
  response.sendFile(path.join(__dirname + "/login.html"));
});

app.post("/auth", function (request, response) {
  var username = request.body.username;
  var password = request.body.password;
  if (username && password) {
    connection.query(
      "SELECT * FROM accounts WHERE username = ? AND password = ?",
      [username, password],
      function (error, results, fields) {
        if (results.length > 0) {
          request.session.loggedin = true;
          request.session.username = username;
          response.redirect("/home");
        } else {
          response.send("Incorrect Username and/or Password!");
        }
        response.end();
      }
    );
  } else {
    response.send("Please enter Username and Password!");
    response.end();
  }
});

app.get("/home", function (request, response) {
  if (request.session.loggedin) {
    response.send("Welcome back, " + request.session.username + "!");
  } else {
    response.send("Please login to view this page!");
  }
  response.end();
});

app.listen(3000);
