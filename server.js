require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
const usersDB = [];

app.get("/users", authenticateToken, (req, res)=>{
    
    return res.json(usersDB);
});

app.post("/users/register", async (req, res)=>{
    try{
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = {
            "email": req.body.email,
            "password": hashedPassword
        };
        usersDB.push(user);
    } catch{
        res.status(500).send();
    }
});

app.post("/users/login", async (req, res) => {
    const user = usersDB.find(user => (user.email === req.body.email));
    if(user == null){
        return res.status(400).send("can't find user");
    }
    try{
        if(await bcrypt.compare(req.body.password, user.password)){
            const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_KEY);
            return res.json({"accessToken": accessToken});
        } else{
            return res.send("Failed");
        }
    } catch{
        return res.status(500).send();
    }
    
});

function authenticateToken(req, res, next){
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(' ')[1];
    if(token == null) return res.send("Unauthorised access: Token Not Passed");
    jwt.verify(token, process.env.ACCESS_TOKEN_KEY, (err, user)=>{
        if(err) return res.send("Invalid token");
        req.user = user;
        next();
    });
}

app.listen(9999, () => console.log("Listening on 9999"));
