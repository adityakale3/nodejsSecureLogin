const jwt = require('jsonwebtoken');

var verifyToken = async (req,res,next) => {
    var token = req.cookies.access_token || '';
    console.log('Middlware Token', token);
    try {
        if (!token) {
          return res.status(401).json('You need to Login')
        }
        const decrypt = await jwt.verify(token, 'secret key');
        req.user = {
          name: decrypt.name,
          email: decrypt.email,
        };
        next();
      } catch (err) {
        return res.status(500).json(err.toString());
      }
}

module.exports = verifyToken;