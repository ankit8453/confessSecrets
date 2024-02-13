require('dotenv').config()
const bodyParser = require("body-parser");
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
//var encrypt = require('mongoose-encryption');
//var md5 = require('md5');
const session = require("express-session");
const passport = require("passport")
//const bcrypt = require('bcrypt');
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require("passport-google-oauth20");
const findOrCreate = require("mongoose-findorcreate");
//const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({
    extended:true
}));

app.use(session({
    secret: "Alubuchiyaalubuchiyaalibuchiya",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const clusterConnectionString = process.env.MONGO_URI;

mongoose.connect(clusterConnectionString, {useNewUrlParser: true});
//mongoose.set("useCreateIndex", true);

const userSchema =new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

/*var secret = process.env.SECRET;
userSchema.plugin(encrypt, { secret: secret,encryptedFields: ['password'] });*/
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User =mongoose.model("User", userSchema);

passport.use(User.createStrategy());

/*passport.serializeUser(function(user, done){
    done(null, user.id);
});

passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});*/

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//get routes api
app.get("/",async(req,res)=>{
    res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] }
));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/login",async(req,res)=>{
    res.render("login");
});

app.get("/register",async(req,res)=>{
    res.render("register");
});

app.get("/secrets", async (req, res) => {
    try {
        const foundUsers = await User.find({ "secret": { $ne: null } });

        if (foundUsers && foundUsers.length > 0) {
            res.render("secrets", { userWithSecrets: foundUsers });
        } else {
            console.log("No users with secrets found");
            // Handle the case where no users with secrets are found
            res.render("secrets", { userWithSecrets: [] }); // or handle it appropriately
        }
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});
 

app.get('/logout', function(req, res, next){
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect('/');
    });
  });

app.get("/submit",function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});  

//post routes API*/

/*app.post("/register",async(req, res) => {

    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const data = new User({
            email: req.body.username,
            password: hash
        });
    
        const val= data.save();
        res.render("secrets");
    });
});*/

app.post("/register",function(req,res){
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    })
});

/*app.post("/login", async (req, res) => {
    const username = req.body.username;
    //const password = md5(req.body.password);
    const password = req.body.password;


    try {
        const foundUser = await User.findOne({ email: username });

        if (foundUser) {
            bcrypt.compare(password, foundUser.password, function(err, result) {
                if (result==true) {
                    res.render("secrets");
                } else {
                    res.render("login", { error: "Incorrect password" });
                }
            });
            if (foundUser.password === password) {
                res.render("secrets");
            } else {
                res.render("login", { error: "Incorrect password" });
            }
        } else {
            res.render("login", { error: "User not found" });
        }
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});*/

app.post("/login", function(req,res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if (err){
            console.log(err);
            
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }    });
})

app.post('/submit', async (req, res) => {
    try {
        const secret = req.body.secret;
        console.log(req.user.id);

        const foundUser = await User.findById(req.user.id);

        if (foundUser) {
            foundUser.secret = secret;
            await foundUser.save();
            res.redirect("/secrets");
        } else {
            console.log("User not found");
            // Handle the case where the user is not found
            res.redirect("/"); // Redirect to the home page or handle it appropriately
        }
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});



app.listen(3000,()=>{
    console.log("server started at port 3000");
});