const express = require("express")
const crypto = require('crypto');
const fs = require('fs');
var mysql = require('mysql');
const Ls = require('passport-local').Strategy
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')

const app = express()
app.set('view engine', 'ejs')

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(flash())
app.use(session({
    secret: '763456765',
    resave: false,
    saveUninitialized: false
}))

var con = mysql.createConnection({
    host: "35.246.147.57",
    user: "root",
    password: "Jupiter.2004",
    database: 'notes'
})

con.connect(function(err) {
    if (err) throw err
    console.log("Connected to SQL server")
    let querry = "SHOW TABLES LIKE 'users'"
    con.query(querry, (err, result) => {
        if (err) throw err
        if(result.length == 0) {
            querry = "CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255), password VARCHAR(255))"
            con.query(querry)
            console.log("Table created")
        }
    })
})

passport.use(new Ls({ usernameField: 'username' }, authuser))
passport.serializeUser((user, done) => {
    done(null, user.id)
})
passport.deserializeUser(async (id, done) => {
    const querry = `SELECT * FROM users WHERE id = '${id}'`
    con.query(querry, (err, result) => {
        if(err) return done(err);
        return done(null, result[0])
    })  
})

app.use(passport.initialize())
app.use(passport.session())


function authuser(username, password, done){
    console.log(`login: ${username}, ${password}`)
    var hash = crypto.createHash('sha256')
    hash.update(password)
    const querry = `SELECT * FROM users WHERE username = '${username}' AND password = '${hash.digest('hex')}'`
    con.query(querry, (err, result) => {
        if(err) return done(e)
        if(result.length == 0) return done(null, false, {message : 'Username sau parola incorecte'})
        else return done(null, result[0])
    })
}

app.get('/', (req, res) => {
    try {
        res.render('index')
    } catch (error) {
        
    }
})

app.get('/code/:file', (req, res) => {
    res.sendFile(req.params.file)
})

app.get('/:file', (req, res) => {
    try {
        res.render(req.params.file)
    } catch (error) {
        
    }
})

app.post('/api/login', passport.authenticate('local', 
{
    successRedirect: '/api/notes', 
    failureRedirect: '/',
    failureFlash: true
}))

app.get('/api/notes', (req, res) => {
    const file = 'users/' + req.user.username
    if (fs.existsSync(file)) {
        req.flash('text', fs.readFileSync(file).toString('utf-8'))
    }
    else {
        fs.writeFileSync(file, '')
        req.flash('text', '')
    }
    res.redirect('/notes')
})

app.post('/api/register', (req, res) => {
    console.log('register request ' + JSON.stringify(req.body))
    let hash = crypto.createHash('sha256')
    hash.update(req.body.password)
    const hashpass = hash.digest('hex')
    const querry = `INSERT INTO users (username, password) VALUES ('${req.body.username}', '${hashpass}')`
    con.query(querry, (err, result) => {
        if(err) throw err;
        console.log('registered user ' + req.body.username)
    })
    res.redirect('/')
})

app.post('/api/notes', (req, res) => {
    const file = 'users/' + req.user.username
    const text = req.body.txt
    try {
        fs.writeFileSync(file, text)
        req.flash('success', 'Salvat cu succes')
    } catch (error) {
        req.flash('error', error)
    }
    req.flash('text', text)
    res.redirect('/notes')
})

const port = process.env.PORT || 80
app.listen(port, () => console.log("listening on port " + port))