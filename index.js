// server/index.js
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import admin from "firebase-admin";
import fetch from "node-fetch";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Load service account key from environment variable
const serviceAccount = JSON.parse(
  Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, "base64").toString(
    "utf8"
  )
);

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

app.post("/exchange-token", async (req, res) => {
  const { authgearToken } = req.body;
  if (!authgearToken) {
    return res.status(400).json({ error: "Missing authgearToken" });
  }

  try {
    // Decode the Authgear token (JWT)
    const payload = JSON.parse(Buffer.from(authgearToken.split(".")[1], "base64").toString("utf8"));

    // Extract the user ID (subject) or custom identifier from the token
    const uid = payload.sub; // You can also extract email, name, etc., if needed

    if (!uid) {
      return res.status(400).json({ error: "UID not found in token" });
    }

    // Create a custom Firebase token with the identifier
    const firebaseToken = await admin.auth().createCustomToken(uid);

    return res.status(200).json({ firebaseToken });
  } catch (error) {
    console.error("Token exchange error:", error);
    return res.status(500).json({ error: "Token exchange failed" });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Authgear ↔ Firebase backend is running on port ${PORT}`);
});
