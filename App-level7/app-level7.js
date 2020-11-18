//jshint esversion:6
// Hashing and Salting using passport

require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({       // Use the package session
  secret: "Our little secret.",   // Key
  resave: false,
  saveUninitialized: false       // For login sesions it should be false
}))

app.use(passport.initialize()); // Initialize passport
app.use(passport.session());  // Use passport to manage our session

mongoose.connect("mongodb://localhost:27017/usersDB", {useNewUrlParser: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);  // It is used to hash and salt the password and to save our users to mongoDB Database
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());       // To create local login strategy

passport.serializeUser(function(user, done) {   // Creates the cookie and stuffs the user's info into it
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {  // Destroys the cookie and discovers the user's info from it
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    // userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

app.get("/auth/google",
passport.authenticate('google', { scope: ['profile'] }));   // authenticates and creates a pop up

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
  res.render("login");
});


app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    } else{
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });

  // if(req.isAuthenticated()){    // if the user is logged in and authenticated then only render secrets.ejs or redirect to login page
  //   res.render("secrets");
  // } else{
  //   res.redirect("/login");
  // }
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else{
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    } else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        })
      }
    }
  });
});

app.get("/logout", function(req, res){
  req.logout();   // logout method is from passport package
  res.redirect("/");
});

app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    } else{
      passport.authenticate("local")(req, res, function(){  // Authenticate the user and if successful then the callback function will be triggered
        res.redirect("/secrets");
        // res.render("secrets");
      });
    }
  });  // register method comes from passport-local-mongoose package, by this we can avaoid creating and saving the user
});

app.post("/login", function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err){    // login method comes from the passport
    if(err){
      console.log(err);
    } else{
      passport.authenticate("local")(req, res, function(){  // Authenticate the user and if successful then the callback function will be triggered
        res.redirect("/secrets");
        // res.render("secrets");
      })
    }
  });  // login method comes from passport
});

// User.find({}, function(err, foundUsers){
//   console.log(foundUsers[2]);   // Logs the 2nd index of foundUsers array
// });




app.listen(3000, function(){
  console.log("Server started at port 3000");
});
