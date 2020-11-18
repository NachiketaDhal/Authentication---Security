//jshint esversion:6
// Hashing and Salting using passport

const express = require("express");
const flash = require("connect-flash");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({       // Use the package session
  secret: "Our little secret.",   // Key
  resave: false,
  saveUninitialized: false       // For login sesions it should be false
}));

app.use(flash());

app.use(passport.initialize()); // Initialize passport
app.use(passport.session());  // Use passport to manage our session

mongoose.connect("mongodb://localhost:27017/usersDB", {useNewUrlParser: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

userSchema.plugin(passportLocalMongoose);  // It is used to hash and salt the password and to save our users to mongoDB Database

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());       // To create local login strategy

passport.serializeUser(User.serializeUser());   // Creates the cookie and stuffs the user's info into it
passport.deserializeUser(User.deserializeUser()); // Destroys the cookie and discovers the user's info from it

app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login");
});


app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  if(req.isAuthenticated()){    // if the user is logged in and authenticated then only render secrets.ejs or redirect to login page
    res.render("secrets");
  } else{
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res){
  req.logout();   // logout method is from passport package
  res.redirect("/");
});

app.post("/register", function(req, res){
  User.findOne({email: req.body.username}, function(err, foundUser) { // checks if the user already exists in our Database or not
    if (err) {
      console.log(err);
    } else if (foundUser) {
      res.send("User already exists");
    } else {
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
}
});
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
