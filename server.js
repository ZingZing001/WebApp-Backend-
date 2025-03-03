require("dotenv").config()
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const cookieParser = require("cookie-parser")
const express = require('express')
const db = require("better-sqlite3")("database.db")
// Set the journal mode to WAL (Write-Ahead Logging) for better concurrency and performance
db.pragma("journal_mode = WAL")

// Database schema
const createTables = db.transaction(() => {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username STRING NOT NULL UNIQUE,
      password STRING NOT NULL)
    `).run()
})

createTables()

const app = express()

app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(express.static('public'))
app.use(cookieParser())

app.use(function (req, res, next) {
  res.locals.errors = []

  // try to decode incoming cookie
  try {
    const decoded = jwt.verify(req.cookies.WebApp, process.env.JWT_SECRET)
    req.user = decoded
  } catch (err) {
    req.user = false
  }

  res.locals.user = req.user
  console.log(req.user)
  next()
})

app.get("/", (req, res) => {
  if (req.user) {
    return res.render("dashboard")
  }
  res.render("homepage")
})

app.get("/login", (req, res) => {
  res.render("login")
})

app.get("/logout", (req, res) => {
  res.clearCookie("WebApp")
  res.redirect("/")
})

app.post("/login", (req, res) => {
  let errors = []

  if (typeof req.body.username !== "string") req.body.username = ""
  if (typeof req.body.password !== "string") req.body.password = ""

  if (req.body.username.trim() == "") errors = ["Invalid username/password"]
  if (req.body.password == "") errors = ["Invalid username/password"]


  if (errors.length) {
    return res.render("login", { errors })
  }

  const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?")

  const userInQuestion = userInQuestionStatement.get(req.body.username)

  if (!userInQuestion) {
    return res.render("login", { errors: ["Invalid username/password"] })
  }
  const passwordMatch = bcrypt.compareSync(req.body.password, userInQuestion.password)

  if (!passwordMatch) {
    return res.render("login", { errors: ["Invalid username/password"] })
  }

  // give the user a cookie
  const token = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000 + 60 * 60 * 24),
      skycolour: "blue",
      ourUser: userInQuestion.id,
      username: userInQuestion.username
    },
    process.env.JWT_SECRET)

  // log the user in by giving them a cookie  
  res.cookie("WebApp", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24
  })

  res.redirect("/")

})


app.post("/register", (req, res) => {
  const errors = []

  if (typeof req.body.username !== "string") req.body.username = ""
  if (typeof req.body.password !== "string") req.body.password = ""

  req.body.username = req.body.username.trim()
  if (!req.body.username) errors.push("Username is required")

  if (req.body.username && req.body.username.length < 3) errors.push("Username must be at least 3 characters long")
  if (req.body.username && req.body.username.length > 20) errors.push("Username must be at most 20 characters long")
  if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters and numbers")

  // check if the username is already taken
  const existingUser = db.prepare("SELECT * FROM users WHERE username = ?").get(req.body.username)
  if (existingUser) errors.push("Username is already taken")

  if (!req.body.password) errors.push("Password is required")
  if (req.body.password && req.body.password.length < 12) errors.push("Password must be at least 12 characters long")
  if (req.body.password && req.body.password.length > 70) errors.push("Password must be at most 20 characters long")

  if (errors.length) {
    return res.render("homepage", { errors })
  }

  // save the new user into a database
  const salt = bcrypt.genSaltSync(10)
  req.body.password = bcrypt.hashSync(req.body.password, salt)

  const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?,?)")
  const result = ourStatement.run(req.body.username, req.body.password)

  const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
  const ourUser = lookupStatement.get(result.lastInsertRowid)

  const token = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000 + 60 * 60 * 24),
      skycolour: "blue",
      ourUser: ourUser.id,
      username: ourUser.username
    },
    process.env.JWT_SECRET)

  // log the user in by giving them a cookie  
  res.cookie("WebApp", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24
  })

  res.redirect("/")
})

app.listen(3000)