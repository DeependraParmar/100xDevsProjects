import express from "express";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import zod from "zod";
import brypt from "bcrypt";
import {User} from "./user.js";
const port = 3000;
const jwtSecret = "eytgndcmvkeo48thdncvh38549ej"

const app = express();
app.use(express.json());

const connectDB = () => {
    mongoose.connect("mongodb+srv://100xdevs:BQ8eKZvriLMq03to@cluster0.sxwb9sq.mongodb.net/todoWithAuth?retryWrites=true&w=majority", {});
    console.log(`MongoDB Connected`);
}
connectDB();

const signUpSchema = zod.object({
    name: zod.string(),
    email: zod.string().email(),
    password: zod.string().min(5).max(20),
});

const loginSchema = zod.object({
    email: zod.string().email(),
    password: zod.string().min(5).max(20),
});

app.get("/", (req,res,next) => {
    res.send("Welcome to the Ultimate Todo App");
});

app.post("/signin", async(req,res,next) => {
    // receiving the data from req.body
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;
    
    // lets do input validation using zod
    const zodResponse = await signUpSchema.safeParse({
        name: name,
        email: email,
        password: password,
    });
    
    // verifying the zodSchema's success
    if(!zodResponse.success){
        return res.status(411).json({
            message: "Invalid Inputs 😟😟"
        });
    }

    // lets check whether user already exists or not
    let user = await User.findOne({email});
    if(user){
        return res.status(401).json({
            success: false,
            message: "User already Exists. Login Instead."
        });
    }

    // lets use the bcrypt to hash the password
    const hashPassword = await brypt.hash(password,10);

    // lets create the user here 
    user = await User.create({
        name: name,
        email: email,
        password: hashPassword,
    });

    // here we go, finally responded back 
    res.status(200).json({
        success: true,
        message: `Hello ${user.name}, you can login now.`
    })
});

app.post("/login", async(req,res,next) => {
    // lets retreive the data from the req.body
    const email = req.body.email;
    const password = req.body.password;

    // input validation via zod against loginSchema 
    const zodResponse = await loginSchema.safeParse({
        email: email,
        password: password
    });

    // if not validated, early returning and giving message
    if(!zodResponse.success){
        return res.status(400).json({
            message: "Invalid Input"
        });
    }

    // let's find the user guys, 
    const user = await User.findOne({email});

    // if user is not found in db, ask him/her to signin first.
    if(!user){
        return res.status(400).json({
            success: false,
            message: "User not found. Sign Up first",
        });
    }

    // now, user is found but password is not matched then 
    const isMatched = await brypt.compare(password, user.password);
    if(!isMatched){
        return res.status(400).json({
            success: false,
            message: "Invalid Email or Password"
        });
    }

    // lets sign the user id and create token to save in browser's cookie.
    const token = jwt.sign({_id: user._id},jwtSecret); 
    res.status(200).cookie("token", token, {
        httpOnly: true,
        expires: new Date(Date.now() + 1000*60*60*60*24*120)
    }).json({
        success: true,
        message: "Logged In Successfully"
    })
})

app.get("/logout", (req,res,next) => {
    // doing nothing, just clearing the cookies now 
    res.status(200).cookie("token", null, {
        expires: new Date(Date.now())
    }).json({
        success: true,
        message: "Logged Out Successfully",
    })
})


app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
})