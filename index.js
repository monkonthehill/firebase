require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');
const morgan = require('morgan');

// Validate environment variables
const requiredEnvVars = [
  'FIREBASE_SERVICE_ACCOUNT_BASE64',
  'AUTHGEAR_ENDPOINT',
  'AUTHGEAR_CLIENT_ID',
  'PORT'
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// Initialize Firebase
let firebaseApp;
try {
  const serviceAccount = JSON.parse(
    Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf-8')
  );

  firebaseApp = admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
} catch (error) {
  console.error('Firebase initialization failed:', error);
  process.exit(1);
}

const app = express();

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  methods: ['POST', 'GET'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10kb' }));
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Health check endpoint
app.get('/', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'authgear-firebase-token-exchange',
    timestamp: new Date().toISOString()
  });
});

// Token exchange endpoint
app.post('/authgear-to-firebase', async (req, res) => {
  try {
    const { authgear_token } = req.body;
    
    if (!authgear_token) {
      return res.status(400).json({ 
        error: 'Missing authgear_token',
        code: 'MISSING_TOKEN'
      });
    }

    // Verify token with Authgear
    const introspectResponse = await axios.post(
      `${process.env.AUTHGEAR_ENDPOINT}/oauth2/token/introspect`,
      {
        client_id: process.env.AUTHGEAR_CLIENT_ID,
        token: authgear_token
      },
      {
        headers: { 'Content-Type': 'application/json' },
        timeout: 5000
      }
    );

    if (!introspectResponse.data?.active) {
      return res.status(401).json({ 
        error: 'Invalid or expired token',
        code: 'INVALID_TOKEN'
      });
    }

    // Get user info
    const userInfoResponse = await axios.get(
      `${process.env.AUTHGEAR_ENDPOINT}/oauth2/userinfo`,
      {
        headers: { Authorization: `Bearer ${authgear_token}` },
        timeout: 5000
      }
    );

    const { sub, email, name } = userInfoResponse.data;

    // Create Firebase custom token
    const firebaseUid = `authgear:${sub}`;
    const firebaseToken = await admin.auth().createCustomToken(firebaseUid);

    res.json({
      success: true,
      firebaseToken,
      user: {
        uid: firebaseUid,
        email,
        name
      }
    });

  } catch (error) {
    console.error('Token exchange error:', error);
    
    if (error.response) {
      // Authgear API error
      console.error('Authgear API error:', {
        status: error.response.status,
        data: error.response.data
      });
      
      return res.status(502).json({
        error: 'Authgear service error',
        code: 'AUTHGEAR_ERROR',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    } else if (error.request) {
      // No response received
      return res.status(504).json({
        error: 'Authgear service timeout',
        code: 'AUTHGEAR_TIMEOUT'
      });
    } else {
      // Other errors
      return res.status(500).json({
        error: 'Internal server error',
        code: 'INTERNAL_ERROR'
      });
    }
  }
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Authgear endpoint: ${process.env.AUTHGEAR_ENDPOINT}`);
});

// Error handling
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});
