const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const axios = require("axios");
const cors = require("cors");
const { URLSearchParams } = require("url");

const app = express();
app.use(cookieParser());

// CORS Middleware
app.use(cors({
    origin: "https://akdevo.github.io", // REMOVE the trailing slash
    credentials: true, // Allows cookies to be sent
    allowedHeaders: ["Content-Type", "Authorization"],
    methods: ["GET", "POST"],
}));

const CLIENT_ID = "5965494195376135434"; 
const CLIENT_SECRET = "RBX-fQg3rLWj8E6MsaB6m7-6FSWrkmdyuvb4fsev65BAsgmmyLQH_mI95NUc2JPYjOe9";
const REDIRECT_URI = "https://bsodscreationsapis.onrender.com/auth/callback/redirect";

// In-memory session store (replace with database in production)
const sessions = {};

// Function to generate a random code_verifier
function generateCodeVerifier() {
    return crypto.randomBytes(32).toString("base64url");
}

// Function to generate code_challenge from the code_verifier
function generateCodeChallenge(codeVerifier) {
    return crypto.createHash("sha256").update(codeVerifier).digest("base64url");
}

// Redirect to Roblox authentication page
app.get("/auth/roblox", async (req, res) => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    // Store code_verifier in a cookie (temporary storage)
    res.cookie("code_verifier", codeVerifier, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 5 * 60 * 1000 // 5 minutes
    });

    // Build the authentication URL
    const authUrl = `https://authorize.roblox.com/?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=openid+profile&state=abc123&code_challenge=${codeChallenge}&code_challenge_method=S256&step=accountConfirm`;

    res.redirect(authUrl);
});

// Handle callback after authentication
app.get("/auth/callback/redirect", async (req, res) => {
    const { code, state } = req.query;
    if (!code) return res.status(400).send("Authentication failed.");
    if (state !== "abc123") return res.status(400).send("Invalid state parameter.");

    // Retrieve code_verifier from cookie
    const codeVerifier = req.cookies.code_verifier;
    if (!codeVerifier) return res.status(500).send("Code verifier missing.");

    try {
        // Exchange authorization code for access token
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

        const { sub: userId, name: username } = userInfoResponse.data; // Get user ID & username

        // Generate a session token
        const sessionToken = crypto.randomBytes(64).toString("hex");

        // Save session info in memory (replace with database in production)
        sessions[sessionToken] = { userId, username, accessToken };

        // Set session cookie
        res.cookie("session", sessionToken, {
            httpOnly: true,
            secure: true,
            sameSite: "None",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        res.redirect("https://akdevo.github.io/bsodscreations/main.html"); // Redirect back to frontend
    } catch (error) {
        console.error(error.response ? error.response.data : error.message);
        res.status(500).send("Authentication error.");
    }
});

// Profile endpoint - Returns logged-in user's info
app.get("/profile", (req, res) => {
    const sessionToken = req.cookies.session;
    if (!sessionToken || !sessions[sessionToken]) {
        return res.json({ authenticated: false });
    }

    const { userId, username } = sessions[sessionToken];

    res.json({
        authenticated: true,
        userId,
        username,
    });
});

// Start the Express server
app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});
