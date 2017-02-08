var bodyParser = require('body-parser');
var bcrypt = require('bcryptjs');
var csrf = require('csurf');
var express = require('express');
var mongoose = require('mongoose');
var sessions = require('client-sessions');

var Schema = mongoose.Schema;
var ObjectId = Schema.ObjectId;

var User =  mongoose.model('User', new Schema({


	id: ObjectId,
	firstName: String,
	lastName: String,
	email: { type: String, unique: true },
	password: String,
}));


var app = express();
app.set('view engine', 'pug');
app.locals.pretty = true;

mongoose.connect('mongodb://localhost/newauth');

//middleware
app.use(bodyParser.urlencoded({extended: true}));

app.use(sessions({
	cookieName: 'session',
	secret:'asdnasdnoqneoqd3oneo231nen1s13jnenw12nwjk12nw1',
	duration: 30 * 60 * 1000,  //expires in time
	activeDuration: 5 * 60 * 1000, //lenghthen the session
	httpOnly: true, //dont let browser js access cookies ever
	secure: true, // only use cookies over https
}));
app.use(csrf());

app.use(function(req, res, next){
	if(req.session && req.session.user){
		User.findOne({email: req.session.user.email }, function(err, user){
			if(user){
				req.user = user;
				delete req.user.password;
				req.session.user =  req.user;
				res.locals.user = req.user;
			}
			next();
		})
	}else{
		next();
	}
});

function requireLogin(req, res, next){
	if(!req.user){
		res.redirect('/login');
	}else{
		next();
	}
}

app.get('/', function(req, res){
	res.render('index.jade');
});

app.get('/register', function(req, res){
	res.render('register.jade', { csrfToken: req.csrfToken() });
});

app.post('/register', function(req, res){
	//res.json(req.body);
	var hash = bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(10));
	var user =  new User({
		firstName: req.body.firstName,
		lastName: req.body.lastName,
		email: req.body.email,
		password: hash,
	});
	user.save(function(err){
		if(err){
			var err = 'Something bad happened';
			if(err.code === 11000){
				error = 'That email is already taken. Try another';
			}
			res.render('register.jade', { error: error });
		}else{
			res.redirect('/dashboard');
		}
	})
});

app.get('/login', function(req, res){
	res.render('login.jade', { csrfToken: req.csrfToken() });
});

app.post('/login', function(req, res){
	User.findOne({email: req.body.email }, function(err, user){
		if(!user){
			res.render('login.jade', { error: 'invalid id or password' });
		}else{
			if(bcrypt.compareSync(req.body.password, user.password)){
				req.session.user = user; //set-cokkie: {email:'..', ..}
				res.redirect('dashboard');
			}else{
				res.render('login.jade', { error: 'invalid id or password' });
			}
		}
	})
});

app.get('/dashboard', requireLogin, function(req, res){
	//console.log('test');
	res.render('dashboard.jade');
});


app.get('/logout', function(req, res){
	req.session.reset();
	res.redirect('/');
});

app.listen(3000);