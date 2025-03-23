/**
 * Authentication utility functions for handling tokens securely
 */

const AuthUtils = {
  /**
   * Generates a cryptographically secure random 32-byte nonce
   * @returns {string} Base64 encoded nonce
   */
  generateSecureNonce() {
    // Create a Uint8Array of 32 random bytes using Web Crypto API
    const randomBytes = new Uint8Array(32);
    window.crypto.getRandomValues(randomBytes);

    // Convert to a Base64 string for transmission
    return this._arrayBufferToBase64(randomBytes);
  },

  /**
   * Validates that a token is in the correct format (Base64-encoded 32-byte value)
   * @param {string} token The token to validate
   * @returns {boolean} True if the token is valid
   */
  validateTokenFormat(token) {
    if (!token) return false;

    try {
      // Try to decode the Base64 string
      const decoded = atob(token);
      // Check if it decodes to 32 bytes
      return decoded.length === 32;
    } catch (e) {
      console.error("Invalid token format", e);
      return false;
    }
  },

  /**
   * Securely stores the authentication token in memory
   * In a production app, you might consider using more secure storage methods
   * @param {string} token The authentication token
   * @returns {string|boolean} The token if valid, false otherwise
   */
  storeToken(token) {
    if (!this.validateTokenFormat(token)) {
      console.error("Attempted to store invalid token format");
      return false;
    }

    // In this simple implementation, we just return the token
    // In a real app, you might encrypt it in memory or use more secure storage
    return token;
  },

  /**
   * Generate and store a new key pair for the current user
   * @returns {Promise<Object>} Object containing the public key for sharing
   */
  async generateAndStoreUserKeys() {
    try {
      // Generate the key pair
      const keyPair = await CryptoUtils.generateKeyPair();

      // Export the keys to storable format
      const publicKeyString = await CryptoUtils.exportPublicKey(
        keyPair.publicKey
      );
      const privateKeyString = await CryptoUtils.exportPrivateKey(
        keyPair.privateKey
      );

      // Store keys in localStorage (in a real app, privateKey would be better secured)
      localStorage.setItem("userPublicKey", publicKeyString);
      localStorage.setItem("userPrivateKey", privateKeyString);

      return {
        publicKey: publicKeyString,
        publicKeyObj: keyPair.publicKey,
        privateKeyObj: keyPair.privateKey,
      };
    } catch (error) {
      console.error("Error generating user keys:", error);
      throw error;
    }
  },

  /**
   * Retrieve the current user's keys
   * @returns {Promise<Object>} Object containing the user's keys
   */
  async getUserKeys() {
    try {
      const publicKeyString = localStorage.getItem("userPublicKey");
      const privateKeyString = localStorage.getItem("userPrivateKey");

      if (!publicKeyString || !privateKeyString) {
        return null;
      }

      try {
        const publicKey = await CryptoUtils.importPublicKey(publicKeyString);
        const privateKey = await CryptoUtils.importPrivateKey(privateKeyString);

        return {
          publicKey,
          privateKey,
          publicKeyString,
        };
      } catch (error) {
        console.error("Error importing user keys:", error);

        // If import fails, try regenerating keys
        console.log("Attempting to regenerate keys...");
        localStorage.removeItem("userPublicKey");
        localStorage.removeItem("userPrivateKey");

        // Return null to trigger key regeneration
        return null;
      }
    } catch (error) {
      console.error("Error in getUserKeys:", error);
      return null;
    }
  },

  /**
   * Store a contact's public key
   * @param {string} username - The username of the contact
   * @param {string} publicKeyString - The contact's public key as a base64 string
   */
  storeContactPublicKey(username, publicKeyString) {
    const contactKeysJson = localStorage.getItem("contactPublicKeys") || "{}";
    const contactKeys = JSON.parse(contactKeysJson);

    contactKeys[username] = publicKeyString;
    localStorage.setItem("contactPublicKeys", JSON.stringify(contactKeys));
  },

  /**
   * Get a contact's public key
   * @param {string} username - The username of the contact
   * @returns {Promise<CryptoKey|null>} The contact's public key or null if not found
   */
  async getContactPublicKey(username) {
    const contactKeysJson = localStorage.getItem("contactPublicKeys") || "{}";
    const contactKeys = JSON.parse(contactKeysJson);

    const publicKeyString = contactKeys[username];
    if (!publicKeyString) {
      return null;
    }

    try {
      return await CryptoUtils.importPublicKey(publicKeyString);
    } catch (error) {
      console.error(`Error importing public key for ${username}:`, error);
      return null;
    }
  },

  /**
   * Helper method to convert ArrayBuffer to Base64 string
   * @private
   */
  _arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  },

  /**
   * Helper method to convert Base64 string to ArrayBuffer
   * @private
   */
  _base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  },
};
