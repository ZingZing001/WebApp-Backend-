const bcrypt = require("bcrypt")
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

app.use(function (req, res, next) {
  res.locals.errors = []
  next()
})

app.get("/", (req, res) => {
  res.render("homepage")
})

app.get("/login", (req, res) => {
  res.render("login")
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

  if (req.body.password && req.body.password.length < 12) errors.push("Password must be at least 12 characters long")
  if (req.body.password && req.body.password.length > 70) errors.push("Password must be at most 20 characters long")

  if (errors.length) {
    return res.render("homepage", { errors })
  }

  // save the new user into a database
  const salt = bcrypt.genSaltSync(10)
  req.body.password = bcrypt.hashSync(req.body.password, salt)

  const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?,?)")
  ourStatement.run(req.body.username, req.body.password)


  // log the user in by giving them a cookie
  res.send("You have been registered")
})

app.listen(3000)