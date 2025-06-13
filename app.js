// Helper function to convert string to ArrayBuffer
function stringToArrayBuffer(str) {
    const encoder = new TextEncoder();
    return encoder.encode(str);
  }
  
  // Helper function to convert ArrayBuffer to string
  function arrayBufferToString(buffer) {
    const decoder = new TextDecoder();
    return decoder.decode(buffer);
  }
  
  // Helper function to generate a key from the password and salt
  async function getKeyFromPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    
    return window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt, // Use the salt passed from encryption
        iterations: 100000,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
  
  // Encrypt message
  async function encryptMessage() {
    const message = document.getElementById("message").value;
    const password = document.getElementById("key").value;
  
    if (!message || !password) {
      alert("Please provide both a message and a key.");
      return;
    }
  
    try {
      // Generate a random salt
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      
      // Generate key from password and salt
      const key = await getKeyFromPassword(password, salt);
      
      // Generate a random Initialization Vector (IV)
      const iv = window.crypto.getRandomValues(new Uint8Array(12)); // AES-GCM requires 12-byte IV
      const encodedMessage = stringToArrayBuffer(message);
  
      // Encrypt the message
      const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedMessage
      );
  
      // Convert encrypted data to Base64 for display
      const encryptedBase64 = arrayBufferToBase64(encrypted);
  
      // Save the salt and IV for decryption
      window.salt = salt;
      window.iv = iv;
  
      // Display the encrypted message and salt (encoded in Base64)
      document.getElementById("encryptedMessage").value = encryptedBase64;
      document.getElementById("encryptedMessage").dataset.salt = arrayBufferToBase64(salt);
      document.getElementById("encryptedMessage").dataset.iv = arrayBufferToBase64(iv);
  
    } catch (err) {
      console.error(err);
      alert("Encryption failed.");
    }
  }
  
  // Decrypt message
  async function decryptMessage() {
    const encryptedMessage = document.getElementById("encryptedMessage").value;
    const password = document.getElementById("key").value;
  
    if (!encryptedMessage || !password) {
      alert("Please provide both encrypted message and key.");
      return;
    }
  
    try {
      const salt = base64ToArrayBuffer(document.getElementById("encryptedMessage").dataset.salt);
      const iv = base64ToArrayBuffer(document.getElementById("encryptedMessage").dataset.iv);
  
      // Generate the key from password and salt
      const key = await getKeyFromPassword(password, salt);
  
      const encryptedBuffer = base64ToArrayBuffer(encryptedMessage);
  
      // Decrypt the message
      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encryptedBuffer
      );
  
      // Convert decrypted data to string
      const decryptedMessage = arrayBufferToString(decrypted);
      document.getElementById("decryptedMessage").value = decryptedMessage;
    } catch (err) {
      console.error(err);
      alert("Decryption failed. Make sure you use the correct key.");
    }
  }
  
  // Convert Base64 to ArrayBuffer
  function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const length = binaryString.length;
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }
  
  // Convert ArrayBuffer to Base64
  function arrayBufferToBase64(buffer) {
    const binary = String.fromCharCode.apply(null, new Uint8Array(buffer));
    return window.btoa(binary);
  }
  