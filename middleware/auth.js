const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req, res, next) {
	//get Token from header
	const tokenHeader = req.header('x-auth-token');
	const tokenUri = req.params.token;
	if (!tokenHeader && tokenUri) {
		//verify token
		try {
			const decode = jwt.verify(tokenUri, config.get('jwtSecret'));

			req.user = decode.user;
			next();
		} catch (err) {
			res.status(401).json({ msg: 'message is not valid' });
		}
	} else if (tokenHeader && !tokenUri) {
		//verify token
		try {
			const decode = jwt.verify(tokenHeader, config.get('jwtSecret'));

			req.user = decode.user;
			next();
		} catch (err) {
			res.status(401).json({ msg: 'message is not valid' });
		}
	} else {
		return res.status(401).json({ msg: 'No Token, Authorization Denied' });
	}
};
