require("dotenv").config();
const express = require("express");
const app = express();
const mongoose = require('mongoose')
const port = 5000;
const cors = require("cors");
const bodyParser = require('body-parser')
app.use(cors());
app.use(express.json());
app.use(express.static("public"));
app.use(express.json());
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.urlencoded({ extended: false })); app.use(express.urlencoded({ extended: false }));
//const accountSid = process.env.ACCOUNT_SID;
//const authToken = process.env.AUTH_TOKEN;;
let twilioNum = process.env.TWILIO_PHONE_NUMBER;
//const client = require("twilio")(accountSid, authToken);
mongoose.connect('mongodb://localhost:27017/otp_tut', { useNewUrlParser: true })
const Schema = mongoose.Schema;
const userSchema = new Schema({
  otp: Number,
  made: Date,
  expires: Date
})
const userSchema2 = new Schema({
  Name: String,
  Password: String
})
const userModel = mongoose.model("User", userSchema)
const userModel2 = mongoose.model("User2", userSchema2)

app.get("/verifyOTP", async (req, res) => {
  res.render("landing2")
})

app.post("/verifyOTP", async (req, res) => {
  let x = await userModel.findOne({ otp: req.body.otp }).exec()
  console.log(x)
  console.log(Date.now())
  if ((x.expires >= Date.now())) {
    console.log("OTP is valid")
    userModel2.findOne({ Name: req.body.name })
      .then(doc => userModel2.updateOne({ _id: doc._id },
        { Password: req.body.password })).
      then(res.render("landing"))
  }
  else {
    console.log("OTP expired")
    res.json({ Status: "OTP is invalid" })
  }
})
let expires = 0
app.post("/sendOTP", async (req, res) => {
  console.log("req",req.body)
  const { from, to } = req.body;
  var otp = 0;
  while (true) {
    otp = Math.floor(100000 + Math.random() * 900000);
    const ttl = 2 * 60 * 1000;
    //two minutes
    expires = Date.now();
    const expires2 = Date.now();
    console.log(expires)
    expires += ttl;
    let x = await userModel.findOne({ otp: otp }).exec()
    if (x) {
      continue;
    }
    else {
      const new_otp = await userModel({
        otp: otp,
        expires: expires,
        made: expires2,
      })
      await new_otp.save();
      break;
    }
  }
  console.log(otp)
  client.messages
    .create({
      body: `Your Otp Is  ${otp}`,
      from: twilioNum,
      to: "+91 6355 581 662",
    })
    .then((messages) => {
      res.status(200).render("landing2")
    })
    .catch((err) => {
      console.error("phone : ", err.message);
      return res.json({ error: err.message });
    });
});
app.get("/", (req, res) => {
  res.render("landing")
})
app.listen(port, () => {
  console.log(`listening on ${port}`);
});


// const auth = async (req, res, next) => {
//     console.log("inside the function", req.cookies.jwt)
//     try {
//         const token = req.cookies.jwt
//         console.log(token)
//         const verifyuser = jwt.verify(token, process.env.SECRET)
//         console.log(verifyuser)
//         const x = await userModel.findOne({ email: verifyuser._id }).exec()
//         console.log(x.email)
//         req.token = token
//         req.user = x
//         next()
//     } catch (err) {
//         console.log("Cookies is not with us")
//         console.log(err)
//         res.json({ Message: 'Sorry could not find the cookies' })
//     }
// }

app.get("/secret", async (req, res) => {
  try {
      console.log("scmkjbvhjdv")
      console.log("COOKIES", req.user)
      res.render("secret")
  } catch (error) {

  }
})
const auth2 = async (req, res, next) => {
  try {
      const token = req.cookies.jwt
      console.log(token)
      const verifyuser = jwt.verify(token, process.env.SECRET)
      console.log(verifyuser)
      const x = await userModel.findOne({ email: verifyuser._id }).exec()
      console.log(x.email)
      req.token = token
      req.user = x
      next()
  } catch (err) {
      res.render('landing', {
          ERROR: 1
      })
  }
}
app.get("/", auth2, (req, res) => {
  res.render("landing")
})

app.post("/signout", async (req, res) => {
  try {
      console.log("User Signout successfuly")
      res.clearCookie("jwt");
      res.json({
          message: "User Signout Sucessfully"
      })
  } catch (err) {
      console.log("error in signout", err)
  }
})



















































const accountSid = "AC7e66ebfd232fa5a099e2efe216067bac"
const authToken = "4295798808c46090d6efc971bce5477e";
const client = require('twilio')(accountSid, authToken);
client.messages
  .create({
      body: 'This is the ship that made the Kessel Run in fourteen parsecs?',
      from: '+916355581662',
      to: '17577810881'
  })
  .then(message => console.log("guya", message.sid));

app.post("/nexmo", async (req, res) => {
  console.log(req.body)
  const response = {}
  try {
      response = await fast2sms.sendMessage(
          {
              authorization: process.env.API_KEY,
              message: req.body.to,
              number: req.body.from,
          })
      console.log(response)
      res.render("login")
  } catch (errr) {
      console.log(errr)
  }
})


app.get("/login", (req, res) => {
  res.render('login')
})

app.get("/fetchform", (req, res) => {
  res.render("fetchform")
})

app.post("/fetchform", async (req, res) => {
  const value = req.body.email;
  const value2 = req.body.username
  console.log(req.body)
  console.log(req.body.username)
  console.log(req.body.email)
  let x = await userModel.findOne({ email: value, username: value2 }).exec()
  console.log(x)
  if (x) {
      console.log("The object is found hurray")
      return res.json({ result: x, result2: 'found' })
  }
  if (x === null) {
      return res.json({ result: 'Not found', result2: 'Sorry' })
  }
  x.then(() => {
      console.log("sfbsfs")
  })
})

app.get("/register", (req, res) => {
  res.render('register')
})


app.post("/register", async (req, res) => {
  console.log(req.body.email)
  const user_before = await userModel.find({ email: req.body.email }).exec()
  console.log(user_before)
  if (user_before.length !== 0) {
      console.log("Mission Abort")
      return res.render("login")
  }
  else {
      try {
          const hashedPw = await bcrypt.hash(req.body.password, 12)
          const token = await createToken(req.body.email)
          const user = new userModel({
              email: req.body.email,
              username: req.body.username,
              password: hashedPw,
              token: token
          })
          //res.cookie(name,value,[options])
          res.cookie("jwt", token, {
              httpOnly: true
          })
          await user.save()
          return res.render('login')
      } catch {
          console.log("Some error")
          return res.render('landing')
      }
  }
})

app.post('/logout', async (req, res) => {
  try {
      res.clearCookie("jwt")
      res.render("landing")
  } catch (err) {
      console.log(err)
  }
})

app.post("/login", async (req, res) => {
  try {
      const email = req.body.email;
      const password = req.body.password;
      const userfound = await userModel.findOne({ email: email })
      console.log(userfound)
      const password_found = await bcrypt.compare(password, userfound.password)
      const token = await createToken(email)
      console.log("This is the token generated by th jwt", token)
      res.cookie("jwt", token, {
          httpOnly: true,
          expires: new Date(Date.now() + 30000),
          secure: true
      })
      if (password_found) {
          res.render('dashboard', {
              UK: userfound
          })
      }
      else {
          res.render('login')
      }
  } catch (error) {
      console.log("error came", error)
  }
})

app.get("/dashboard", async (req, res) => {
  try {
      res.render("dashboards")
  }
  catch (error) {
      console.log("Error in the cookie authentication")
  }
})

