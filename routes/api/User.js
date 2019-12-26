const express = require('express');
const router = express.Router();

const auth = require('../../middleware/auth');
// user models
const User = require('../../models/Users');

// @route    GET api/get users
// @desc     Test Route
// @access   Public

router.get('/', auth, async (req, res) => {
	try {
		const user = await User.findById(req.user.id).select('-password');
		return res.json(user);
	} catch (err) {
		return res.status(500).send('Server Error');
	}
});

module.exports = router;
