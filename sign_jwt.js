// sign_jwt.js
const fs  = require('fs');
const jwt = require('jsonwebtoken');

const privKey = fs.readFileSync('./keys/jwt_priv.pem');
const token = jwt.sign(
  { iss: 'yolo.com', sub: 'bob$yolo.com' },
  privKey,
  { algorithm: 'RS256', expiresIn: '1h' }
);

console.log(token);
