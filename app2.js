const express = require('express')
require('dotenv').config()
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const fast2sms = require('fast-two-sms')
const cors = require('cors')
const mongoose = require('mongoose')
const { ObjectId } = mongoose.Schema
var nodemailer = require('nodemailer')
const bcrypt = require('bcrypt')
const cookieParser = require('cookie-parser')
const Nexmo = require('nexmo')
const braintree = require('braintree')
const _ = require('lodash')
const app = express()
const path = require('path')
const { syncBuiltinESMExports } = require('module')
const { EsimProfileContext } = require('twilio/lib/rest/supersim/v1/esimProfile')
var formidable = require("formidable");
require('ejs')
let twilioNum = process.env.TWILIO_PHONE_NUMBER;
app.use(cookieParser());
app.use(express.static("public"));
app.use(express.json());
app.use(cors())

const accountSid = "AC7e66ebfd232fa5a099e2efe216067bac"
const authToken = "786bc0de6744384539523c41963b0b64";
const client = require('twilio')(accountSid, authToken);
const fs = require('fs')
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.urlencoded({ extended: false }));

mongoose.connect('mongodb://localhost:27017/reactback_tut', { useNewUrlParser: true })

const Schema = mongoose.Schema;
//var Jwt = require('express-jwt')
var { expressjwt: jwtk } = require("express-jwt");
const { sortBy, intersection } = require('lodash')
const { Console } = require('console')
const { getMaxListeners } = require('process')

const gateway = new braintree.BraintreeGateway({
    environment: braintree.Environment.Sandbox,
    merchantId: "mgwfh374gs9wrz6c",
    publicKey: "q46rw944jp52rgrn",
    privateKey: "202c12d08f54a39286601f551461b33b",
})

const Category = new Schema({
    name: {
        type: String,
        trim: true,
        required: true,
        maxlength: 32,
        unique: true
    }
},
    { timestamps: true }
)


const OTPschema = new Schema({
    otp: Number,
    made: Date,
    expires: Date,
    to: String
},
    { timestamps: true }
)
const Otp_Model = mongoose.model("OTP", OTPschema)


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
    purchases: [{
        _id: String,
        name: String,
        description: String,
        category: String,
        quantity: Number,
        amount: Number,
        transaction_id: {},
    }]
    ,
    mobile: String,
    address: {
        type: String,
        required: true
    },
    role: {
        type: String,
        required: true
    },
})
const userModel = mongoose.model("User", userSchema)
const CategoryModel = mongoose.model("Category", Category)
const Product = new Schema({
    name: {
        type: String,
        trim: true,
        required: true,
        maxlength: 32,
    },
    description: {
        type: String,
        trim: true,
        required: true,
        maxlength: 2000,
    },
    price: {
        type: Number,
        required: true,
        maxlength: 32,
        trim: true
    },
    category: {
        type: ObjectId,
        ref: "Category",
        required: true
    },
    stock: {
        type: Number,
        //  min: 0
    },
    sold: {
        type: Number,
        default: 0
    },
    photo: {
        data: Buffer,
        contentType: String
    }
},
    { timestamps: true }
)
const Product_model = mongoose.model("Products", Product)

const OrderSchema = new mongoose.Schema(
    {
        products: [Product],
        transaction_id: {},
        amount: { type: Number },
        address: { type: String },
        status: {
            type: String,
            default: "Recieved",
            enum: ["Cancelled", "Delivered", "Shipped", "Processing", "Recieved"]
        },
        updated: Date,
        user: {
            type: ObjectId,
            ref: "User"
        }
    },
    { timestamps: true }
);

const Order = mongoose.model("Order", OrderSchema);

var isSignedIn = jwtk(
    {
        secret: process.env.SECRET,
        userProperty: "auth1",
        algorithms: ['sha1', 'HS256', 'RS256']
    })

const getAllproducts = async (req, res) => {
    console.log("products i am getting ", req.query.sortBy)
    let limit = req.query.limit ? parseInt(req.query.limit) : 8
    let sortBy = req.query.sortBy ? req.query.sortBy : "category"
    console.log(sortBy)
    Product_model.find().
        sort([['category']]).
        select("-photo").
        limit(limit).
        exec(
            (err, products) => {
                if (err) {
                    return res.status(400).json({
                        error: "No products found"
                    })
                }
                console.log("]hgsgzgzffgz")
                // console.log("products",products[])
                products.forEach(element => {
                    console.log(element.name)
                });
                return res.json(products)
            }
        )
}
const updateStock = async (req, res, next) => {
    console.log("dfvjhgvjagfuergfuaerfeg")
    let myOperations = req.body.order.products.map(prod => {
        return {
            updateOne: {
                filter: { _id: prod._id, stock: { $gte: prod.count } },
                update: { $inc: { stock: -prod.count, sold: +prod.count } }
            }
        }
    })
    Product_model.bulkWrite(myOperations, {}, (err, products) => {
        console.log(products.nModified)
        console.log(products)
        if (products.nModified === 0) {
            console.log(products.nModified)
            console.log("wefnkfbvkjbvkjab")
            return res.status(400).json({
                error: "Bulk Operations Failed"
            })
        }
        else {
            next()
        }
    })
}
const pushOrderInPurchaseList = (req, res, next) => {
    let purchases = [];
    console.log("finally we are here to purchase our order", req.body)
    req.body.order.products.forEach(product => {
        console.log("-------------------->", product)
        purchases.push({
            _id: product._id,
            name: product.name,
            description: product.description,
            category: product.category,
            quantity: product.count,
            amount: req.body.order.amount,
            transaction_id: req.body.order.transaction_id
        });
    });

    userModel.findOneAndUpdate(
        { _id: req.profile._id },
        { $push: { purchases: purchases } },
        { new: true },
        (err, purchases) => {
            if (err) {
                return res.status(400).json({
                    error: "Unable to save purchase list"
                });
            }
            next();
        }
    );
};

const isAuthencticated = async (req, res, next) => {
    try {

        console.log(req.profile._id.toString())
        console.log("req auth is", req.auth)
        console.log("req profile is", req.profile)
        let checker = req.profile && req.auth &&
            req.profile._id.toString() === req.auth._id
        if (!checker) {
            return res.status(403).json({
                error: "Acess is denied"
            })
        }
        next()
    } catch (er) {
        console.log(er)
    }
}

const createToken = async (id) => {
    const x = jwt.sign({ _id: id }, process.env.SECRET)
    return x;
}

const getOrderById = (req, res, next, id) => {
    Order.findById(id)
        .exec((err, order) => {
            if (err) {
                return res.status(400).json({
                    error: "NO order found in DB"
                });
            }
            req.order = order;
            next();
        });
}
const getAllOrders = (req, res) => {
    Order.find()
        .populate("user", "_id name")
        .exec((err, order) => {
            if (err) {
                return res.status(400).json({
                    error: "No orders found in DB"
                });
            }
            res.json(order);
        });
}

const getOrderStatus = (req, res, next) => {
    // res.json(Order.schema.path("status").enumValues);
    Order.find().exec((err, orders) => {
        if (err) {
            return res.status(400).json({
                error: "Order didnt fetched"
            })
        }
        else {
            return res.json(orders)
        }
    })
};
const getStatus = (req, res) => {
    res.json(Order.schema.path("status").enumValues);
};
const updateStatus = (req, res) => {
    console.log("Here we come and welcome,fjelferl", req.body, req.body.status)
    Order.updateOne(
        { _id: req.body.orderId },
        { $set: { status: req.body.status.status } },
        (err, order) => {
            if (err) {
                console.log(err)
                return res.status(400).json({
                    error: "Cannot update order status"
                });
            }
            console.log("It was successful")
            res.json(order);
        }
    );
};
const getAllUniqueCategory = async (req, res) => {
    Product_model.distinct("category", {}, (err, category) => {
        if (err) {
            return res.status(400).json({
                error: "No category found"
            })
        }
        res.json(category)
    })
}
const isAdmin = async (req, res, next) => {
    try {
        console.log(req.auth)
        if (req.auth.role === '0') {
            return res.status(403).json({
                error: "Not an Admin access denied"
            })
        }
        console.log("ExITING THE admin ")
        next();
    } catch (e) {
        console.log("error is here")
        console.log(e)
    }
}
const createCategory = (req, res) => {
    try {
        console.log(req.body)
        const category = new CategoryModel(req.body)
        category.save((err, category) => {
            if (err) {
                return res.status(403).json({
                    error: "Not able to save in Db"
                })
            }
            res.json({ category })
        })
    } catch (err) {
        console.log(err)
    }
}

const getCategory = (req, res) => {
    const category = req.category
    console.log("category in get category", category)
    return res.json(category)
}

const getOrder = (req, res) => {
    const order = req.order
    console.log("category in get category", order)
    return res.json(order)
}

const getAllCategory = (req, res) => {
    CategoryModel.find().exec((err, items) => {
        if (err) {
            return res.status(400).json({
                error: "Categories nor found"
            })
        }
        res.json(items)
    })
}
const updateCategory = async (req, res) => {
    console.log("++++++++++++++++++++++++++++")
    console.log(req)
    const category = req.category
    category.name = req.body.name
    console.log("category while being updated", req.category)
    category.save((err, updated) => {
        if (err) {
            console.log(err)
            return res.status(400).json({
                error: "Failed to save"
            })
        }
        res.json(updated)
    })
}
const removeCategory = async (req, res) => {
    console.log("Removing the category here", req.category._id)
    const category = req.category
    const products = await Product_model.deleteMany({ category: req.category._id })
    console.log("products", products)
    category.remove((err, deleted) => {
        if (err) {
            return res.status(400).json({
                error: "Failed to Delete"
            })
        }
        res.json(deleted)
    })
}
const getCategoryById = (req, res, next, id) => {
    CategoryModel.findById(id).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: "No user found in Db"
            })
        }
        console.log(user)
        req.category = user;
        next()
    })
}

const getUserById = (req, res, next, id) => {
    console.log(id)
    userModel.findById(id).exec((err, user) => {
        if (err || !user) {
            console.log("error is here 1", err)
            return res.status(400).json({
                error: "No user found in Db"
            })
        }
        console.log("user is here ", user)
        req.profile = user;
        next()
    })
}
const getUserDetails = (req, res, id) => {
    console.log("geting the user by id", id)
    console.log(req.profile._id)
    userModel.findById(req.profile._id).exec((err, user) => {
        if (err || !user) {
            console.log("error is here for the 2", err)
            return res.status(400).json({
                error: "No user found in Db"
            })
        }
        console.log("user is here ", user)
        res.json(user)
    })
}

const getuserorderdetails = (req, res, id) => {
    console.log("geting the user by id", id)
    console.log(req.profile._id)
    Order.find({ user: req.profile._id }).exec((err, order) => {
        if (err || !order) {
            console.log("error is here 3", err)
            return res.status(400).json({
                error: "No order found in Db"
            })
        }
        console.log("order is here ", order)
        res.json(order)
    })
}
const getUser = (req, res) => {
    return res.json(req.profile)
}
const getProduct = (req, res) => {
    console.log(req.product)
    req.product.photo = undefined;
    return res.json(req.product)
}
const updateProduct = (req, res) => {
    let form = new formidable.IncomingForm()
    form.keepExtensions = true
    form.parse(req, (err, fields, file) => {
        if (err) {
            return res.status(400).json({
                error: "Problem with image"
            })
        }
        let product = req.product
        console.log(">>>>>>>>>>>>>>>>>>>>>", product)
        product = _.extend(product, fields)
        console.log("field down there ", fields)
        console.log("ppppppppppppppppppppp", product)
        console.log("photo")
        product.save((err, productupdated) => {
            if (err) {
                console.log(err)
                return res.status(400).json({
                    error: "Updating the tshirt In DB failed"
                })
            }
            console.log("updation was a success", productupdated)
            res.json(productupdated)
        })
    })
}

const deleteProduct = (req, res) => {
    console.log("inside the delete ", req)
    let product = req.product;
    product.remove((err, deletedproduct) => {
        console.log("error is here for the sex", err)
        if (err) {
            return res.status(400).json({
                error: "Failed to delete the product"
            })
        }
        res.json({
            message: "Deletion was successfull",
            deletedproduct
        })
    })

}
const removeOrder = (req, res) => {
    console.log("inside teh remove", req.params.orderId)
    console.log(req.order)
    let order = req.order
    console.log(">>>>>>>>>>>>>>>>>>>>>", order)
    order.status = "Cancelled"
    order.save((err, orderupdate) => {
        if (err) {
            console.log(err)
            return res.status(400).json({
                error: "Updating the tshirt In DB failed"
            })
        }
        console.log("updation was a success", orderupdate)
        res.json(orderupdate)
    })
}
const getphoto = (req, res, next) => {
    console.log("Fetching out the photgraph")
    if (req.product.photo.data) {
        res.set("Content-type", req.product.photo.contentType)
        return res.send(req.product.photo.data)
    }
    next();
}
const getProductbyId = (req, res, next, id) => {
    console.log("fkffdhuifdv", id)
    // console.log(req,"product id is here with me =>",id)
    Product_model.findById(id).exec((err, product) => {
        if (err) {
            console.log("error is here 5", err)
            return res.status(400).json({
                error: "Product not found"
            })
        }
        req.product = product;
        next()
    })
}
const createOrder = (req, res) => {
    console.log("creating the order")
    console.log(req.profile)
    console.log(req.body)
    req.body.order.user = req.profile;
    const order = new Order(req.body.order);
    console.log("order", order)
    console.log("req.bodu.order.user =>", req.body.order.user)
    console.log("req.bodu.order =>", req.body.order)
    order.save((err, order) => {
        // order["address"] = (req.profile.address)
        console.log("order is here =>", order)
        if (err) {
            console.log("error was there", err)
            return res.status(400).json({
                error: "Failed to save your order in DB"
            });
        }
        else {
            return res.status(200).json(order);
        }
    });
};

const createProduct = (req, res) => {
    let form = new formidable.IncomingForm()
    console.log(form)
    form.keepExtensions = true
    form.parse(req, (err, fields, file) => {
        if (err) {
            console.log(err)
            return res.status(400).json({
                error: "Problem with image"
            })
        }
        console.log("Here are the fields", fields)
        console.log("Here are the fields", file)
        const { name, description, price, category, stock } = fields
        console.log({ name, description, price, category, stock })
        if (!name || !description || !price || !category || !stock) {
            return res.status(400).json({
                error: "Please Include All the fields"
            })
        }
        let product = new Product_model(fields)
        console.log(file.photo.size)
        console.log(file.photo.path)
        console.log(file.photo.filepath)
        if (file.photo) {
            if (file.photo.size > 300000) {
                return res.status(400).json({
                    error: "File size is too big"
                })
            }
        }
        product.photo.data = fs.readFileSync(file.photo.filepath)
        product.photo.contentType = file.photo.type
        product.save((err, product) => {
            if (err) {

                console.log("error is here 8", err)
                return res.status(400).json({
                    error: "Saving the tshirt In DB failed"
                })
            }
            return res.json(product)
        })
    })
}
const get_Token = (req, res) => {
    console.log("dfghujiiyterwrsedtyuioytrrfghuij")
    gateway.clientToken.generate({}, function (err, response) {
        if (err) {
            return res.status(500).send(err)
        }
        else {
            return res.json(response)
        }
    })
}
const processPayment = (req, res) => {
    console.log('ofhdhgjl')
    let nonceFromTheClient = req.body.paymentMethodNonce
    let amountFromTheClient = req.body.amount
    console.log(req.body.amount)
    console.log(req.body.paymentMethodNonce)
    gateway.transaction.sale({
        amount: amountFromTheClient,
        paymentMethodNonce: nonceFromTheClient,
        options: {
            submitForSettlement: true
        }
    }, function (err, result) {
        if (err) {
            console.log("error is here", err)
            return res.status(500).json(err)
        } else {
            return res.json(result)
        }
    })
}

app.param("userId", getUserById)
app.param("orderId", getOrderById);
app.param("/user/:userId", getUser)




app.param("productId", getProductbyId)
app.param("categoryId", getCategoryById)
app.get("/order/:orderId", getOrder)
app.get("/category/:categoryId", getCategory)
app.get("/categories", getAllCategory)
app.get("/pr/:productId", getProduct)
app.get("/product/:productId", getProduct)
app.get("/ph/photo/:productId", getphoto)
app.get("/products", getAllproducts)



app.post("/verifyOTP", async (req, res) => {

    let form = new formidable.IncomingForm()
    form.keepExtensions = true
    form.parse(req, async (err, fields, file) => {
        console.log("fields ot verify",fields)
        let x = await Otp_Model.findOne({ otp: fields.otp }).exec()
        if (x) {
            let currentTime = Date.now()
            let diff = x.expires - currentTime
            if (diff < 0) {
                return res.json({ error: 'OTP is invallid' })
            } else {
                let user = await userModel.findOne({ email: x.to })
                console.log("",user)
                if (user.password === fields.password) {
                    return res.json({ error: 'same password' })
                }
                user.password = fields.password
                console.log("password reset successfully",user,fields.password)                
                user.save()
                return res.json({ error: 'OTP was valid and it is saved successfully' })
            }
        }
    })

})

app.post("/sendOTP", async (req, res) => {
    let form = new formidable.IncomingForm()
    form.keepExtensions = true
    form.parse(req, async (err, fields, file) => {
        console.log('fields', fields)
        const { email } = fields;
        var otp = 0;
        let expires = 0;
        const otp_model = await Otp_Model.find()
        if (otp_model.length === 0) {
            otp = Math.floor(100000 + Math.random() * 900000);
            const ttl = 2 * 60 * 1000;
            //two minutes
            expires = Date.now();
            const expires2 = Date.now();
            //   console.log(expires)
            expires += ttl;
            let x = await userModel.findOne({ otp: otp }).exec()
            const new_otp = await Otp_Model({
                otp: otp,
                expires: expires,
                made: expires2,
                to: `${email}`
            })
            await new_otp.save();
            var transporter = nodemailer.createTransport({
                service: 'gmail',
                host: 'smtp.gmail.com',
                port: 465,
                secure: true,
                auth: {
                    user: '20bt04049@gsfcuniversity.ac.in',
                    pass: 'TarunLT@23'
                }
            });
            var mailOptions = {
                from: '20bt04049@gsfcuniversity.ac.in',
                to: `${email}`,
                subject: 'Sending you the email',
                html: `<h1>Welcome to you</h1><p>${otp} valid for 2 minute only</p>`
            };
            transporter.sendMail(mailOptions, function (err, info) {
                if (err) {
                    return res.status(200).json({ error: info })
                    // console.log('Error',err)
                }
                else {
                    console.log("Email Sent" + info.response)
                    return res.status(200).json(info)
                }
            })
        }
        else {
            while (true) {
                otp = Math.floor(100000 + Math.random() * 900000);
                const ttl = 2 * 60 * 1000;
                //two minutes
                expires = Date.now();
                const expires2 = Date.now();
                console.log(expires)
                expires += ttl;
                let x = await Otp_Model.findOne({ otp: otp }).exec()
                console.log("x", x)
                if (x) {
                    continue;
                }
                else {
                    const new_otp = await Otp_Model({
                        otp: otp,
                        expires: expires,
                        made: expires2,
                        to: `${email}`
                    })
                    await new_otp.save();
                    break;
                }
            }
            var transporter = nodemailer.createTransport({
                service: 'gmail',
                host: 'smtp.gmail.com',
                port: 465,
                secure: true,
                auth: {
                    user: '20bt04049@gsfcuniversity.ac.in',
                    pass: 'TarunLT@23'
                }
            });
            var mailOptions = {
                from: '20bt04049@gsfcuniversity.ac.in',
                to: `${email}`,
                subject: 'Sending you the email',
                html: `<h1>Welcome to you</h1><p>${otp} valid for 2 minute only</p>`
            };
            transporter.sendMail(mailOptions, function (err, info) {
                if (err) {
                    return res.status(200).json({ error: info })
                    // console.log('Error',err)
                }
                else {
                    console.log("Email Sent" + info.response)
                    return res.status(200).json(info)
                }
            })
        }

    })
}
)
app.get("/products/categories", getAllUniqueCategory)
app.get("/india/payment/gettoken/:userId",
    isSignedIn,
    isAuthencticated
    , get_Token)




app.post("/signin", async (req, res) => {
    console.log("In the sign in")
    try {
        console.log("kdbvhfdvad")
        const record = await
            userModel.findOne(
                { email: req.body.email, password: req.body.password }
            )
        console.log(record)
        if (!record) {
            return res.json({ error: "Error in user finding" })
        }
        const token = jwt.sign({
            password: req.body.password,
            email: req.body.password, _id: record._id
        },
            process.env.SECRET)
        res.cookie("jwt", token, { expiresIn: new Date() + 9999 })
        const { _id, email, password, username, address, role } = record
        return res.json({ token, user: { _id, email, password, username, role, address } })
    } catch (err) {
        console.log("There is some error down there", err)
        return res.json({ error: "Error aagyi" })
    }
})


// const record = new userModel({
//     username: "Tarun",
//     email: "123@gmail.com",
//     password: "asdfghjkl",
//     role: "1",
//     address:"AJwa"
// })
// record.save()
app.post("/signup", async (req, res) => {

    console.log("'hhdaragf ftdhrdyr hxt shtsstst")
    console.log(req.body)
    try {
        const _record = await new userModel({
            username: req.body.name,
            email: req.body.email,
            password: req.body.password,
            role: req.body.role,
            address: req.body.address,
        })
        await _record.save()
        const token = await createToken(req.body.email)
        res.cookie("jwt", token, {
            httpOnly: true
        })
        return res.json({ _record })
    }
    catch (err) {
        console.log(err)
        return res.json({ error: "Error in singup" })
    }
})

app.post("/payment/braintree/:userId", isSignedIn, isAuthencticated, processPayment, createOrder)

app.post("/order/create/:userId", isSignedIn, isAuthencticated, pushOrderInPurchaseList, updateStock, createOrder);

app.get("/order/all/:userId", isSignedIn, isAuthencticated, isAdmin, getAllOrders);

app.get("/users/orders/:userId", isSignedIn, isAuthencticated, getUserDetails);

const changinguserdetails = (req, res) => {
    userModel.findByIdAndUpdate(req.auth._id,
        {
            username: req.body.name,
            email: req.body.emailid,
            address: req.body.addressuser,
            password: req.body.passworduser
        }
    ).exec((err, userupdate) => {
        if (err) {
            return res.json({
                error: "Sorry error in update"
            })
        }
        else {
            console.log(userupdate)
            return res.json(userupdate)
        }
    })
}

app.get("/users/:userId", isSignedIn, isAuthencticated, getuserorderdetails);
app.put("/users/:userId", isSignedIn, isAuthencticated, changinguserdetails);
app.get("/order/status/:userId", isSignedIn,
    isAuthencticated,
    isAdmin,
    getOrderStatus
);
app.get("/order/status/admin/:userId", isSignedIn,
    isAuthencticated,
    isAdmin,
    getStatus);


app.put(
    "/order/:orderId/status/:userId",
    isSignedIn,
    isAuthencticated,
    isAdmin,
    updateStatus
);

app.post("/cr/:userId",
    isSignedIn,
    isAuthencticated,
    isAdmin,
    createCategory)

app.post("/pr/:userId",
    isSignedIn,
    isAuthencticated,
    isAdmin,
    createProduct)

app.delete("/pr/:productId/:userId",
    isSignedIn,
    isAuthencticated,
    isAdmin,
    deleteProduct,
)
app.put("/order/:userId/:orderId",
    isSignedIn,
    isAuthencticated,
    removeOrder,
)
app.put("/pr/:productId/:userId",
    isSignedIn,
    isAuthencticated,
    isAdmin,
    updateProduct,
)
app.put("/cri/:categoryId/:userId",
    isSignedIn,
    isAuthencticated,
    isAdmin
    , updateCategory)
app.delete("/cri/:categoryId/:userId",
    isSignedIn,
    isAuthencticated,
    isAdmin,
    removeCategory)
app.listen(8000, function () {
    console.log("On the port 8000")
})