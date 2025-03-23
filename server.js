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
    origin: "https://akdevo.github.io/", // Change this to match your frontend domain
    credentials: true, // Allow sending cookies across origins
}));

const CLIENT_ID = "5965494195376135434"; // Replace with your actual Roblox App ID
const CLIENT_SECRET = "RBX-fQg3rLWj8E6MsaB6m7-6FSWrkmdyuvb4fsev65BAsgmmyLQH_mI95NUc2JPYjOe9"; // Replace with your Roblox secret
const REDIRECT_URI = "https://bsodscreationsapis.onrender.com/auth/callback/redirect"; // Your public API callback URL

// Function to generate a random code_verifier
function generateCodeVerifier() {
    const buffer = crypto.randomBytes(32);
    return buffer.toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

// Function to generate code_challenge from the code_verifier
function generateCodeChallenge(codeVerifier) {
    return crypto.createHash("sha256").update(codeVerifier).digest("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
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
        const response = await axios.post("https://apis.roblox.com/oauth/v1/token", new URLSearchParams({
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            code,
            grant_type: "authorization_code",
            redirect_uri: REDIRECT_URI,
            code_verifier: codeVerifier,
        }).toString(), {
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const accessToken = response.data.access_token;

        // Generate a session token
        const sessionToken = crypto.randomBytes(128).toString("hex");

        // Set session cookie
        res.cookie("session", sessionToken, {
            httpOnly: true,
            secure: true,  // Ensure cookies work on HTTPS only
            sameSite: "None",  // Allow cross-site cookies
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        res.send("Login successful! You can now access the site.");
    } catch (error) {
        console.error(error.response ? error.response.data : error.message);
        res.status(500).send("Authentication error.");
    }
});

// Profile page (for testing purposes)
app.get("/profile", (req, res) => {
    const session = req.cookies.session;
    if (!session) {
        return res.status(401).send("Not logged in.");
    }
    res.send(`Logged in with session: ${session}`);
});

// Start the Express server
app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});
