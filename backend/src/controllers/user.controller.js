import { asyncHandler } from '../utils/AsyncHandler.js';
import { ApiError } from '../utils/ApiError.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import { User } from '../models/User.model.js';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';



const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);
        console.log("User in method",user)
        const accessToken = user.generateAccessToken()
        console.log("accessToken",accessToken)
        const refreshToken = await user.generateRefreshToken()
        

        //we are storing refresh token in database only for logged-in users not for the new registered ones
        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false }) //validateBeforeSave is set to false because we are not validating the password while saving the refresh token
        return { accessToken, refreshToken }
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating tokens")
    }
}


const registerUser = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;

    if([username, email, password].some((field) => field?.trim() === "")){
        throw ApiError(400, "All fields are required");
    }

    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })

    if(existedUser){
        throw ApiError(400, "User with email or username already exists");
    }

    const user = await User.create({
        username: username?.toLowerCase(),
        email,
        password
    })

    const createdUser = await User.findById(user._id).select("-password");

    if(!createdUser){
        throw new ApiError(500, "Something went wrong while registering")
    }

    return res
        .status(201)
        .json(new ApiResponse(201, createdUser, "User created successfully"));
});


const loginUser = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;

    if(!username && !email){
        throw new ApiError(400, "Username or email is required");
    }

    const user = await User.findOne({
        $or: [{ username }, { email }]
    })

    if(!user){
        throw new ApiError(404, "User does not exist");
    }

    const isPasswordValid = await user.comparePassword(password)
    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid user Credentials")
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true, //This means that the cookie can only be accessed by the server
        secure: true
    }


    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(new ApiResponse(
            200,
            { user: loggedInUser, accessToken, refreshToken },
            "User Logged In Successfully"
        )    
    )
})


const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(req.user._id,
        {
            $unset: {
                refreshToken: 1 //This is used to remove the refresh token from the database
            },

        },
        {
            new: true //This is to get the updated instance of the user(refreshToken = undefined) rather then old where there is a refresh token value
        })
    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged Out"))
})


export { registerUser, loginUser, logoutUser }