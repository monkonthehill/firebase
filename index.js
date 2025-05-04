require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const { initializeFirebaseAdmin } = require('./firebase-admin');
const { initializeAuthgear } = require('./authgear-setup');

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize services
initializeFirebaseAdmin();
const authgearClient = initializeAuthgear();

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*'
}));
app.use(morgan('dev'));
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Token exchange endpoint
app.post('/exchange-token', async (req, res) => {
  try {
    const { authgearToken } = req.body;
    
    if (!authgearToken) {
      return res.status(400).json({ error: 'Missing authgearToken' });
    }

    // Verify Authgear token
    const authgearUser = await authgearClient.verifyIDToken(authgearToken);
    
    // Create Firebase custom token using the Authgear user ID
    const firebaseToken = await admin.auth().createCustomToken(authgearUser.sub, {
      // You can add custom claims here if needed
      'https://authgear.com/claims/user/is_verified': authgearUser.is_verified,
      'https://authgear.com/claims/user/email': authgearUser.email
    });
    
    res.json({ 
      firebaseToken,
      authgearUser: {
        id: authgearUser.sub,
        email: authgearUser.email,
        is_verified: authgearUser.is_verified
      }
    });
  } catch (error) {
    console.error('Token exchange error:', error);
    
    if (error.name === 'AuthgearError' && error.reason === 'InvalidToken') {
      return res.status(401).json({ error: 'Invalid Authgear token' });
    }
    
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something broke!' });
});

app.listen(PORT, () => {
  console.log(`Token exchange service running on port ${PORT}`);
});
