const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(403).json({ error: 'No token provided' });

    jwt.verify(token, 'SECRET_KEY', (err, decoded) => {
        if (err) return res.status(500).json({ error: 'Failed to authenticate token' });
        req.user = decoded;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ error: 'Access denied' });
    next();
};

module.exports = { verifyToken, isAdmin };
