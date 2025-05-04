require("dotenv").config();
const express = require("express");
const axios = require("axios");
const cors = require("cors");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");

// Decode Firebase service account from base64 env var
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

// POST /authgear-to-firebase - receives Authgear access token, returns Firebase custom token
app.post("/authgear-to-firebase", async (req, res) => {
  try {
    const { authgear_token } = req.body;
    if (!authgear_token) {
      return res.status(400).json({ error: "Missing authgear_token" });
    }

    // Step 1: Get user info from Authgear
    const userInfoResponse = await axios.get(`${AUTHGEAR_ENDPOINT}/oauth2/userinfo`, {
      headers: {
        Authorization: `Bearer ${authgear_token}`,
      },
    });

    const userInfo = userInfoResponse.data;

    // Step 2: Use Authgear user ID to create Firebase UID
    const firebaseUid = `authgear:${userInfo.sub}`;

    // Step 3: Create Firebase custom token
    const customToken = await admin.auth().createCustomToken(firebaseUid);

    return res.status(200).json({ firebaseToken: customToken });
  } catch (error) {
    console.error("Error in /authgear-to-firebase:", error.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Root route (optional health check)
app.get("/", (req, res) => {
  res.send("Authgear ↔ Firebase backend is running.");
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
