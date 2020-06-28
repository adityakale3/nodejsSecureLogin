const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const { validationResult,check,matchedData, sanitizeBody } = require('express-validator');
var cookieParser = require('cookie-parser');
var verifyToken = require('./checklogin')

var urlencodedParser = bodyParser.urlencoded({ extended: false });
app.use(cookieParser());
app.use(bodyParser.json());
app.use(express.static('./views'));
app.set('view engine','ejs');
app.set('views','./views');
var con=mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "school"
});
con.connect(function(err){
    if(err) throw err;
    console.log('DB Connected');
    });

app.get('/', (req,res) => {
    res.render('login', {msg: "" , errors: ""});
});

app.get('/reg', (req,res) => {
    res.render('reg',{errors: "", data: ""});
});


app.post('/reg', urlencodedParser, [
    check('username', 'Username must be an Email').isEmail().withMessage('Username must be an Email'),
    check('name').not().isEmpty().withMessage('Should not be empty').isLength({min:5}).withMessage('Must be at least 5 chars long'),
    check('password').isLength({min : 5}).withMessage('Must be at least 5 chars long'),
    check('cpassword').custom((value , {req}) => {
        if(value != req.body.password){
            throw new Error('Confirm password should be same as Password');
        }
        return true;
    })
] ,(req,res) => {
    const errors = validationResult(req);
    console.log(errors.mapped());
    if (!errors.isEmpty()) {
        const allData = matchedData(req);
        return res.render('reg', {errors: errors.mapped(), data : allData});
    }else{
        // GET VALUES
        var email = req.body.username;
        var name = req.body.name;
        var password = req.body.password;
        // BCRYPT PASSWORD
        bcrypt.hash(password, 10, function(err, hash) {
            // SQL QUERY
            var insertQuery='INSERT INTO `users` (`name`,`email`,`password`) VALUES (?,?,?)';
            var query=mysql.format(insertQuery,[name,email,hash]);
            con.query(query,function(err,response){
                 if(err){ throw err; }
                 else{

                }
                });
        });

        res.render('login', {msg: "Registered Successfully" , errors: ""});
    }

});

app.post('/', urlencodedParser, [
    check('username', 'Username must be an Email').isEmail().withMessage('Username must be an Email')
], (req,res) => {

    const errors = validationResult(req);
    console.log(errors.mapped());
    if (!errors.isEmpty()) {
        const allData = matchedData(req);
        return res.render('login', {errors: errors.mapped(), msg : "Error"});
    }else{
        // GET USER VALUES
        var email = req.body.username;
        var password = req.body.password;
        // CHECK USER by email
        var getQuery="SELECT * FROM `users` WHERE email = ?";
        var query=mysql.format(getQuery,[email]);
        con.query(query,function(err,dbData){   
           if(err) throw err;
            // ON DB DATA
                // CHECK IF USER WITH EMAIL EXIST
                if(dbData.length > 0){
                    bcrypt.compare(password, dbData[0].password, function(err, result) {
                        if(result){
                            // IF ALL OK, Genrate Token and SET COOKIE
                            var token = jwt.sign({ email: email, name:dbData[0].name }, 'secret key', {expiresIn:'1h'});
                            console.log('===================');
                            console.log('DB Password ', dbData[0].password);
                            console.log('Token ', token);
                            console.log('===================');
                            res.cookie('access_token', token, {
                                maxAge:3600000 ,
                                httpOnly:true
                            });
                            res.redirect('/home');
                        }else{
                            res.render('login', {msg: "Auth Failed", errors: ""});
                        }
                    });
                }else{
                    res.render('login', {msg: "Auth Failed", errors: ""});
                }


        });
    }
});

app.get('/home', verifyToken ,(req,res) => {
    res.render('home', {userDetails : {name : req.user.name , email : req.user.email} });
});

app.get('/logout', (req,res) => {
    res.clearCookie('access_token');
    res.redirect('/');
});

app.listen(3000, () => {
    console.log('Up & Running');
});
