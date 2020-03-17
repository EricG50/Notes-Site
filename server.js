const express = require('express');
const bcrypt = require('bcrypt');
const fs = require('fs');
var mysql = require('mysql');
const Ls = require('passport-local').Strategy;
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');

const app = express();
app.set('view engine', 'ejs');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(flash());
app.use(
	session({
		secret: '763456765',
		resave: false,
		saveUninitialized: false
	})
);

var con = mysql.createConnection({
	host: '35.246.147.57',
	user: 'root',
	password: 'Jupiter.2004',
	database: 'notes'
});

con.connect(function(err) {
	if (err) throw err;
	log('Connected to SQL server');
	let querry = "SHOW TABLES LIKE 'users'";
	con.query(querry, (err, result) => {
		if (err) throw err;
		if (result.length == 0) {
			querry =
				'CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255), password VARCHAR(255))';
			con.query(querry);
			log('Table created');
		}
	});
});

passport.use(new Ls({ usernameField: 'username' }, authuser));
passport.serializeUser((user, done) => {
	done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
	const querry = `SELECT * FROM users WHERE id = '${id}'`;
	con.query(querry, (err, result) => {
		if (err) return done(err);
		return done(null, result[0]);
	});
});

app.use(passport.initialize());
app.use(passport.session());

function authuser(username, password, done) {
	log(`login: ${username}, ${password}`);
	const querry = `SELECT * FROM users WHERE username = '${username}'`;
	con.query(querry, (err, result) => {
		if (err) return done(err);
		if (result.length == 0) return done(null, false, { message: 'Username incorect' });
		else {
			if (bcrypt.compareSync(password, result[0].password)) return done(null, result[0]);
			else return done(null, false, 'Parola incorecta');
		}
	});
}

function log(txt) {
	console.log(txt);
	const time = new Date(Date.now());
	logtxt = `[${time.toUTCString()}]: ${txt}\n`;
	fs.appendFileSync('log.txt', txt + '\n');
}

function logRequest(req) {
	const time = new Date(Date.now());
	const logobj = {
		url: req.originalUrl,
		user: req.user,
		method: req.route.stack[0].method,
		time: time.toUTCString(),
		body: req.body,
		params: req.params,
		ip: req.ip,
		route: req.route
	};
	fs.appendFileSync('requestslog.txt', JSON.stringify(logobj) + '\n');
}

function flashError(req, res, err, dest) {
	log('error: ' + err);
	req.flash('error', err);
	res.redirect(dest);
}

app.get('/', (req, res) => {
	logRequest(req);
	try {
		res.render('index');
	} catch (error) {
		res.sendStatus(500);
	}
});

app.get('/register', (req, res) => {
	logRequest(req);
	try {
		res.render('register');
	} catch (error) {
		log(error);
		res.send(error);
		res.sendStatus(500);
	}
});

app.post(
	'/api/login',
	passport.authenticate('local', {
		successRedirect: '/notes',
		failureRedirect: '/',
		failureFlash: true
	})
);

app.post('/api/register', (req, res) => {
	logRequest(req);
	try {
		console.log('register request ' + JSON.stringify(req.body));
		let querry = `SELECT * FROM users WHERE username = '${req.body.username}'`;
		con.query(querry, (e, r) => {
			if (e) throw e;
			if (r.length > 0) return flashError(req, res, 'Username indisponibil', '/register');
			const hashpass = bcrypt.hashSync(req.body.password, 10);
			querry = `INSERT INTO users (username, password) VALUES ('${req.body.username}', '${hashpass}')`;
			con.query(querry, (err, result) => {
				if (err) throw e;
				querry = `CREATE TABLE ${req.body.username} (name VARCHAR(255), date BIGINT, text TEXT)`;
				con.query(querry, (error, r) => {
					if (error) return flashError(error);
					log('created table ' + req.body.username);
					log('registered user ' + req.body.username);
					res.redirect('/');
				});
			});
		});
	} catch (error) {
		log(error);
		res.send(error);
		res.sendStatus(500);
	}
});

app.get('/notes', (req, res) => {
    logRequest(req);
    if (!req.user) return res.redirect('/');
	try {
		const querry = `SELECT * from ${req.user.username}`;
		con.query(querry, (err, result) => {
            if (err) throw err;
            req.flash('notes', JSON.stringify(result));
            res.render('noteslist');
		});
	} catch (error) {
		log(error);
		res.send(error);
		res.sendStatus(500);
	}
});

app.get('/api/create/:name', (req, res) => {
    logRequest(req);
	if (!req.user) return res.redirect('/');
	try {
		const username = req.user.username;
		const name = req.params.name;
		let querry = `SELECT * from ${username} WHERE name = '${name}'`;
		con.query(querry, (err, result) => {
			if (err) throw err;
			if (result.length > 0) return flashError(req, res, 'Nume deja folosit');
			querry = `INSERT INTO ${username} VALUES ('${name}', ${Date.now()}, ' ')`;
			con.query(querry, (e, r) => {
				if (e) throw e;
				res.redirect('/notes');
			});
		});
	} catch (error) {
		log(error);
		res.send(error);
		res.sendStatus(500);
	}
});

app.get('/api/note', (req, res) => {
	logRequest(req);
	if (!req.user) return res.redirect('/');
	const file = 'users/' + req.user.username;
	if (fs.existsSync(file)) {
		req.flash('text', fs.readFileSync(file).toString('utf-8'));
	} else {
		fs.writeFileSync(file, '');
		req.flash('text', '');
	}
	res.redirect('/notes');
});

app.post('/api/note', (req, res) => {
	logRequest(req);
	if (!req.user) return res.redirect('/');
	const file = 'users/' + req.user.username;
	const text = req.body.txt;
	try {
		fs.writeFileSync(file, text);
		req.flash('success', 'Salvat cu succes');
	} catch (error) {
		req.flash('error', error);
	}
	req.flash('text', text);
	res.redirect('/notes');
});

app.get('/:file', (req, res) => {
	logRequest(req);
	try {
		const file = req.params.file;
		if (fs.existsSync(file)) {
			res.sendFile(file);
		} else {
			res.sendStatus(404);
		}
	} catch (error) {
		log(error);
		res.send(error);
		res.sendStatus(500);
	}
});

app.get('/api/logout', (req, res) => {
    logRequest(req);
	try {
        req.logout()
        res.redirect('/')
	} catch (error) {
		log(error);
		res.send(error);
		res.sendStatus(500);
	}
})

const port = process.env.PORT || 80;
app.listen(port, () => log('listening on port ' + port));
