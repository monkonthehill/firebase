require("dotenv").config();
const express = require("express");
const axios = require("axios");
const cors = require("cors");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");

// Initialize Firebase Admin
const serviceAccount = JSON.parse(
  Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, "base64").toString("utf-8")
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
app.use(cors());
app.use(bodyParser.json());

const AUTHGEAR_ENDPOINT = process.env.AUTHGEAR_ENDPOINT;
const AUTHGEAR_CLIENT_ID = process.env.AUTHGEAR_CLIENT_ID;

// Enhanced error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// POST /authgear-to-firebase
app.post("/authgear-to-firebase", async (req, res) => {
  try {
    const { authgear_token } = req.body;
    
    if (!authgear_token) {
      return res.status(400).json({ error: "Missing authgear_token" });
    }

    // Verify token with Authgear
    const tokenResponse = await axios.post(
      `${AUTHGEAR_ENDPOINT}/oauth2/token/introspect`,
      {
        client_id: AUTHGEAR_CLIENT_ID,
        token: authgear_token
      },
      {
        headers: { 'Content-Type': 'application/json' }
      }
    );

    if (!tokenResponse.data.active) {
      return res.status(401).json({ error: "Invalid token" });
    }

    // Get user info
    const [userInfoResponse, userDetailsResponse] = await Promise.all([
      axios.get(`${AUTHGEAR_ENDPOINT}/oauth2/userinfo`, {
        headers: { Authorization: `Bearer ${authgear_token}` }
      }),
      axios.get(`${AUTHGEAR_ENDPOINT}/users/${tokenResponse.data.sub}`, {
        headers: { Authorization: `Bearer ${authgear_token}` }
      })
    ]);

    const userInfo = userInfoResponse.data;
    const userDetails = userDetailsResponse.data;

    // Get the primary identifier (email or phone)
    const primaryIdentity = userDetails.identities?.find(id => id.type === 'login_id');
    const identifier = primaryIdentity?.claims?.email || primaryIdentity?.claims?.phone_number;

    // Create Firebase UID
    const firebaseUid = `authgear:${userInfo.sub}`;

    // Create or update Firebase user
    try {
      await admin.auth().updateUser(firebaseUid, {
        email: userInfo.email || identifier,
        emailVerified: true,
        displayName: userInfo.name || '',
      });
    } catch (error) {
      if (error.code === 'auth/user-not-found') {
        await admin.auth().createUser({
          uid: firebaseUid,
          email: userInfo.email || identifier,
          emailVerified: true,
          displayName: userInfo.name || '',
        });
      } else {
        throw error;
      }
    }

    // Create custom token
    const customToken = await admin.auth().createCustomToken(firebaseUid);

    res.status(200).json({
      firebaseToken: customToken,
      identifier: identifier,
      email: userInfo.email,
      name: userInfo.name
    });

  } catch (error) {
    console.error("Authgear-Firebase token exchange failed:", error);
    
    // Provide more detailed error information
    const statusCode = error.response?.status || 500;
    const errorMessage = error.response?.data?.error || error.message || 'Token exchange failed';
    
    res.status(statusCode).json({ 
      error: errorMessage,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

app.get("/", (req, res) => {
  res.send("Authgear ↔ Firebase token exchange service is running");
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
