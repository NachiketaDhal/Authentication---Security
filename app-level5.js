//jshint esversion:6
// Hashing + Salting

const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRound = 10;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

mongoose.connect("mongodb://localhost:27017/usersDB", {
  useNewUrlParser: true
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

const User = mongoose.model("User", userSchema);

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/login", function(req, res) {
  res.render("login");
});


app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/logout", function(req, res){
  res.redirect("/");
});

app.post("/register", function(req, res) {
  User.findOne({
    email: req.body.username
  }, function(err, foundUser) { // checks if the user already exists in our Database or not
    if (err) {
      console.log(err);
    } else if (foundUser) {
      res.send("User already exists");
    } else {
      bcrypt.hash(req.body.password, saltRound, function(err, hash) { // password entered by the user has been hashed with 10 saltRounds
        const newUser = new User({
          email: req.body.username,
          password: hash
        });
        newUser.save(function(err) {
          if (err) {
            console.log(err);
          } else {
            res.render("secrets");
          }
        });
      });
    }

  });
});

app.post("/login", function(req, res) {
  const userName = req.body.username;
  const password = req.body.password;
  User.findOne({
    email: userName
  }, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, function(err, result) { // compares the password entered by the user with the password stored in DB
          if (result === true) {
            res.render("secrets");
          } else{
            res.send("Invalid Username or Password")
          }
        });
      }
    }
  });
});

// User.find({}, function(err, foundUsers){
//   console.log(foundUsers[2]);   // Logs the 2nd index of foundUsers array
// });




app.listen(3000, function() {
  console.log("Server started at port 3000");
});
