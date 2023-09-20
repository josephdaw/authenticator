const jwt = require('jsonwebtoken');

function authMiddleware(req, res, next) {
  const apiKeyHeader = req.headers['x-api-key'];
  const authHeader = req.headers.authorization;

  if (apiKeyHeader) {
    if (apiKeyHeader !== process.env.API_KEY) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    next();
  } else if (authHeader) {
    const token = authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Token missing' });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  } else {
    return res.status(401).json({ error: 'Authorization header missing' });
  }
}

module.exports = authMiddleware;