//jshint esversion:6
// username and password only in plane text

const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

mongoose.connect("mongodb://localhost:27017/usersDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

const User = mongoose.model("User", userSchema);

app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login");
});


app.get("/register", function(req, res){
  res.render("register");
});

app.post("/register", function(req, res){
  User.findOne({email: req.body.username}, function(err, foundUser){  // checks if the user already exists in our Database or not
    if(err){
      console.log(err);
    } else if (foundUser) {
      res.send("User already exists");
    } else{
      const newUser = new User({
        email: req.body.username,
        password: req.body.password
      });
      newUser.save(function(err){
        if(err){
          console.log(err);
        } else{
          res.render("secrets");
        }
      });
    }
  });

});

app.post("/login", function(req, res){
  const userName = req.body.username;
  const password = req.body.password;

  User.findOne({email: userName}, function(err, foundUser){
    if(err){
      res.send("Invalid Username or password.");
    } else{
      if(foundUser){
        if(foundUser.password === password){
          res.render("secrets");
        }
      }
    }
  });
});

// User.find({}, function(err, foundUsers){
//   console.log(foundUsers[2]);   // Logs the 2nd index of foundUsers array
// });




app.listen(3000, function(){
  console.log("Server started at port 3000");
});
