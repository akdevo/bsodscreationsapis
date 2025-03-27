require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const axios = require("axios");
const cors = require("cors");
const mongoose = require("mongoose");
const { URLSearchParams } = require("url");

const app = express();
app.use(cookieParser());
app.use(cors({
    origin: "https://akdevo.github.io",
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
    methods: ["GET", "POST"],
}));

// Environment variables for security
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const MONGO_URI = process.env.MONGO_URI;

// MongoDB Connection
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.error("MongoDB Connection Error:", err));

// Define session schema
const sessionSchema = new mongoose.Schema({
    sessionToken: { type: String, required: true, unique: true },
    userId: { type: String, required: true },
    username: { type: String, required: true },
    accessToken: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: "7d" } // Auto-delete after 7 days
});

const Session = mongoose.model("Session", sessionSchema);

// Utility functions
function generateCodeVerifier() {
    return crypto.randomBytes(32).toString("base64url");
}

function generateCodeChallenge(codeVerifier) {
    return crypto.createHash("sha256").update(codeVerifier).digest("base64url");
}

// Roblox authentication route
app.get("/auth/roblox", (req, res) => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    res.cookie("code_verifier", codeVerifier, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 5 * 60 * 1000
    });

    const authUrl = `https://authorize.roblox.com/?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=openid+profile&state=abc123&code_challenge=${codeChallenge}&code_challenge_method=S256&step=accountConfirm`;

    res.redirect(authUrl);
});

// Handle authentication callback
app.get("/auth/callback/redirect", async (req, res) => {
    const { code, state } = req.query;
    if (!code || state !== "abc123") return res.status(400).send("Authentication failed.");

    const codeVerifier = req.cookies.code_verifier;
    if (!codeVerifier) return res.status(500).send("Code verifier missing.");

    try {
        const tokenResponse = await axios.post("https://apis.roblox.com/oauth/v1/token", new URLSearchParams({
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            code,
            grant_type: "authorization_code",
            redirect_uri: REDIRECT_URI,
            code_verifier: codeVerifier,
        }).toString(), {
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const accessToken = tokenResponse.data.access_token;

        // Fetch user info from Roblox API
        const userInfoResponse = await axios.get("https://apis.roblox.com/oauth/v1/userinfo", {
            headers: { Authorization: `Bearer ${accessToken}` },
        });

        const { sub: userId, name: username } = userInfoResponse.data;

        const sessionToken = crypto.randomBytes(64).toString("hex");

        // Store session in MongoDB
        await Session.create({ sessionToken, userId, username, accessToken });

        res.cookie("session", sessionToken, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.redirect("https://akdevo.github.io/bsodscreations/main.html");
    } catch (error) {
        console.error(error.response ? error.response.data : error.message);
        res.status(500).send("Authentication error.");
    }
});

// Profile endpoint
app.get("/profile", async (req, res) => {
    const sessionToken = req.cookies.session;
    if (!sessionToken) return res.json({ authenticated: false });

    const session = await Session.findOne({ sessionToken });
    if (!session) return res.json({ authenticated: false });

    res.json({ authenticated: true, userId: session.userId, username: session.username });
});

// Start server
app.listen(3000, () => console.log("Server running on http://localhost:3000"));
