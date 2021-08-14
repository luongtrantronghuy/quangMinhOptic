const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const secrets = require('../data/secrets');
const db = require('./db');

exports.authenticate = async (req, res) => {
  const {username, password} = req.body;
  const user = await db.find(username);
  let check = false;
  if (user) {
    check = (user.username === username) &&
      (bcrypt.compareSync(password, user.info.password));
  }
  if (check) {
    const accessToken = jwt.sign(
        {username: user.username, access: user.access},
        secrets.accessToken, {
          expiresIn: '24h',
          algorithm: 'HS256',
        });
    res.status(200).json({accessToken: accessToken, access: user.access});
  } else {
    res.status(401).send('Username or password incorrect');
  }
};

exports.check = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, secrets.accessToken, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};
