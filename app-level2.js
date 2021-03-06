//jshint esversion:6
// In our Database the encrypted password is stored instead of the original password

const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

mongoose.connect("mongodb://localhost:27017/usersDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

const secret = "Thisisourlittlesecret";   // Encryption Key
userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });  // encryption field should be added after the model creation
 // When we use save() the mongoose will automatically encrypt the required fields and in case of find() it will decrypt those required fields

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
  const newUser = new User({
    email: req.body.username,
    password: req.body.password
  });
  newUser.save(function(err){   // save() --> password encrypted
    if(err){
      console.log(err);
    } else{
      res.render("secrets");
    }
  });
});

app.post("/login", function(req, res){
  const userName = req.body.username;
  const password = req.body.password;

  User.findOne({email: userName}, function(err, foundUser){   // find()--> password decrypted
    if(err){
      res.send("Invalid Username or password.");
    } else{
      if(foundUser){
        if(foundUser.password === password){    // checks if password is matching or not
          res.render("secrets");
        }
      }
    }
  });
});






app.listen(3000, function(){
  console.log("Server started at port 3000");
});
