const express = require('express')
require('dotenv').config()
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const mongoose = require('mongoose')
//jwt token is data attached with cookies in encrypted manner
const bcrypt = require('bcrypt')
const cookieParser = require('cookie-parser')
const req = require('express/lib/request')
const app = express()
require('ejs')
app.use(cookieParser())
app.use(express.urlencoded({ extended: true }))
app.set('view engine', 'ejs')
mongoose.connect('mongodb://localhost:27017/jwt_tut', { useNewUrlParser: true })

const Schema = mongoose.Schema;
const userSchema = new Schema({
    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    token: {
        type:String,
    }
})
const userModel = mongoose.model("User", userSchema)
app.use(express.urlencoded({ extended: true }))

// userSchema.methods.generateAuthToken = async function(){
//     console.log(this._id)
//     try{
//         const token = jwt.sign({_id:this._id},"istolethesexthatbelongedtodevendra") 
//     }catch(error){
//     }
// }
const auth = async(req,res,next)=>{
    console.log(req.cookies.jwt)
    try{
        const token = req.cookies.jwt
        console.log(token)
        const verifyuser = jwt.verify(token,process.env.SECRET)
        console.log(verifyuser)
        const x = await userModel.findOne({email:verifyuser._id}).exec()
        console.log(x.email)
        req.token = token
        req.user = x
        next()
    }catch(err){
        console.log(err)
    }
}

app.get("/fetchform",(req,res)=>{
    res.render("fetchform")
})
app.get("/secret",auth,async(req,res)=>{
    try{
    res.render("secret")
    }catch(error){
        console.log("gaand phatt gyi")
        res.render("landing")
    }
})
app.get("/", (req, res) => {
    console.log("efoui")
    res.render('landing')
})


app.get("/login", (req, res) => {
    res.render('login')
})


app.get("/register", (req, res) => {
    res.render('register')
})


app.post("/register", async (req, res) => {
    const user_before = await userModel.find({email:req.body.email}).exec()
    console.log(user_before)
    if(user_before.length!==0){
        console.log("Mission Abort")
        return res.render("login")
    }
    else{
    try{
    const hashedPw = await bcrypt.hash(req.body.password, 12)
    const token = await createToken(req.body.email)
    const user = new userModel({
        email: req.body.email,
        username: req.body.username,
        password: hashedPw,
        token:token
    })
    //res.cookie(name,value,[options])
    res.cookie("jwt",token,{
        httpOnly:true,
        expires:new Date(Date.now()+3000)
    })
    await user.save()
    return res.render('login')
    }catch{
        console.log("Some error")
    return res.render('landing')
    }
}
})

app.post('/logout',auth,async(req,res)=>{
    try{
        res.clearCookie("jwt")
        res.render("landing")
        }catch(err){
        console.log(err)
    }
})

app.post("/login",async(req,res)=>{
    try{
        const email = req.body.email;
        const password = req.body.password;
        const userfound = await userModel.findOne({email:email})
        const password_found = await bcrypt.compare(password,userfound.password)
        const token = await createToken(email)
        res.cookie("jwt",token,{
            httpOnly:true,
            expires:new Date(Date.now()+30000),
            secure:true
        })
        if(password_found){
            res.render('dashboard',{
                UK:userfound.username
            })
        }
        else{
            res.render('login')
        }
    }catch(error){
        console.log("error came",error)
    }
})

const createToken = async (id) => {
    const x = jwt.sign({ _id:id}, process.env.SECRET)
    return x;
}

app.listen(3000, function () {
    console.log("On the port 3000")
})