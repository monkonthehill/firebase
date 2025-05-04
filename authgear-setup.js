const { authgear } = require('@authgear/core');

let authgearClient;

const initializeAuthgear = () => {
  if (authgearClient) {
    return authgearClient;
  }

  try {
    authgearClient = new Authgear.default({
      endpoint: process.env.AUTHGEAR_ENDPOINT,
      clientID: process.env.AUTHGEAR_CLIENT_ID,
    });

    console.log('Authgear client initialized successfully');
    return authgearClient;
  } catch (error) {
    console.error('Failed to initialize Authgear client:', error);
    throw error;
  }
};

module.exports = {
  initializeAuthgear,
  getAuthgearClient: () => {
    if (!authgearClient) {
      throw new Error('Authgear client not initialized');
    }
    return authgearClient;
  }
};
