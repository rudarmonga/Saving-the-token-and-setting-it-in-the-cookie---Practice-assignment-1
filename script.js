const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Secret keys
const jwtSecret = 'ShivanshGarg';
const aesSecret = '1234567890123456';
const iv = crypto.randomBytes(16);

// Encrypt the payload and return encrypted token
const encrypt = (payload) => {
  const token = jwt.sign(payload, jwtSecret);
  const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(aesSecret), iv);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted; // prepend IV for use in decryption
};

// Decrypt the token and return decoded payload
const decrypt = (token) => {
  const [ivHex, encryptedToken] = token.split(':');
  const ivBuffer = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(aesSecret), ivBuffer);
  let decrypted = decipher.update(encryptedToken, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return jwt.verify(decrypted, jwtSecret);
};

module.exports = {
  encrypt,
  decrypt
};
