const admin = require('firebase-admin');

let firebaseAdminInitialized = false;

const initializeFirebaseAdmin = () => {
  if (firebaseAdminInitialized) {
    return admin;
  }

  try {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
      }),
      databaseURL: process.env.FIREBASE_DATABASE_URL
    });

    firebaseAdminInitialized = true;
    console.log('Firebase Admin initialized successfully');
    return admin;
  } catch (error) {
    console.error('Failed to initialize Firebase Admin:', error);
    throw error;
  }
};

module.exports = {
  initializeFirebaseAdmin,
  getAdmin: () => {
    if (!firebaseAdminInitialized) {
      throw new Error('Firebase Admin not initialized');
    }
    return admin;
  }
};
