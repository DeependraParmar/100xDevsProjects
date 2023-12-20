import { User } from "./user";
import jwt from "jsonwebtoken";
const jwtSecret = "eytgndcmvkeo48thdncvh38549ej"

export const isAuthenticated = async(req,res,next) => {
    const {token} = req.cookies;
    if(!token){
        return res.status(403).json({
            success: false,
            message: "Unauthorised Access. Login First",
        });
    }

    const verifiedUserId = await jwt.verify(token, jwtSecret);
    req.user = await User.findOne(verifiedUserId._id);
    next();
}