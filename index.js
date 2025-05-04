require("dotenv").config();
const express = require("express");
const axios = require("axios");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const admin = require("firebase-admin");
const morgan = require("morgan");

// Initialize Firebase Admin with better error handling
let firebaseApp;
try {
  const serviceAccount = JSON.parse(
    Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, "base64").toString("utf-8")
  );

  firebaseApp = admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
} catch (error) {
  console.error("Failed to initialize Firebase Admin:", error);
  process.exit(1);
}

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(",") || "*",
  methods: ["POST", "GET"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Logging
app.use(morgan("combined"));

// Body parsing with size limit
app.use(express.json({ limit: "10kb" }));

// Configuration
const {
  AUTHGEAR_ENDPOINT,
  AUTHGEAR_CLIENT_ID,
  PORT = 4000,
  NODE_ENV = "development"
} = process.env;

// Health check endpoint
app.get("/", (req, res) => {
  res.json({
    status: "healthy",
    service: "authgear-firebase-token-exchange",
    environment: NODE_ENV,
    timestamp: new Date().toISOString()
  });
});

// Token exchange endpoint
app.post("/authgear-to-firebase", async (req, res) => {
  try {
    // Validate input
    const { authgear_token } = req.body;
    if (!authgear_token) {
      return res.status(400).json({ 
        error: "Missing required field: authgear_token" 
      });
    }

    // Verify token with Authgear
    let tokenInfo;
    try {
      const response = await axios.post(
        `${AUTHGEAR_ENDPOINT}/oauth2/token/introspect`,
        {
          client_id: AUTHGEAR_CLIENT_ID,
          token: authgear_token
        },
        {
          headers: { "Content-Type": "application/json" },
          timeout: 5000 // 5 second timeout
        }
      );
      
      tokenInfo = response.data;
      
      if (!tokenInfo.active) {
        return res.status(401).json({ error: "Invalid or expired token" });
      }
    } catch (error) {
      console.error("Authgear token verification failed:", error.message);
      return res.status(502).json({ 
        error: "Failed to verify token with Authgear",
        details: NODE_ENV === "development" ? error.message : undefined
      });
    }

    // Fetch user details
    let userInfo, userDetails;
    try {
      [userInfo, userDetails] = await Promise.all([
        axios.get(`${AUTHGEAR_ENDPOINT}/oauth2/userinfo`, {
          headers: { Authorization: `Bearer ${authgear_token}` },
          timeout: 5000
        }),
        axios.get(`${AUTHGEAR_ENDPOINT}/users/${tokenInfo.sub}`, {
          headers: { Authorization: `Bearer ${authgear_token}` },
          timeout: 5000
        })
      ]);
    } catch (error) {
      console.error("Failed to fetch user details:", error.message);
      return res.status(502).json({ 
        error: "Failed to fetch user details from Authgear",
        details: NODE_ENV === "development" ? error.message : undefined
      });
    }

    // Extract user information
    const primaryIdentity = userDetails.data.identities?.find(id => id.type === "login_id");
    const identifier = primaryIdentity?.claims?.email || primaryIdentity?.claims?.phone_number;
    const email = userInfo.data.email || identifier;
    const name = userInfo.data.name || "";

    if (!email) {
      return res.status(400).json({ 
        error: "No email or phone number found for user" 
      });
    }

    // Create Firebase user
    const firebaseUid = `authgear:${tokenInfo.sub}`;
    
    try {
      await admin.auth().updateUser(firebaseUid, {
        email,
        emailVerified: true,
        displayName: name,
      });
    } catch (error) {
      if (error.code === "auth/user-not-found") {
        await admin.auth().createUser({
          uid: firebaseUid,
          email,
          emailVerified: true,
          displayName: name,
        });
      } else {
        throw error;
      }
    }

    // Generate Firebase custom token
    const firebaseToken = await admin.auth().createCustomToken(firebaseUid);

    // Successful response
    res.json({
      success: true,
      firebaseToken,
      user: {
        uid: firebaseUid,
        email,
        name,
        identifier
      }
    });

  } catch (error) {
    console.error("Token exchange error:", error);
    
    const statusCode = error.code?.startsWith("auth/") ? 400 : 500;
    const errorMessage = error.code ? error.message : "Internal server error";
    
    res.status(statusCode).json({ 
      error: errorMessage,
      details: NODE_ENV === "development" ? error.stack : undefined
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ 
    error: "Internal server error",
    details: NODE_ENV === "development" ? err.message : undefined
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`Server running in ${NODE_ENV} mode on port ${PORT}`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received. Shutting down gracefully...");
  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  console.log("SIGINT received. Shutting down gracefully...");
  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });
});
