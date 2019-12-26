const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const config = require('config');
const { check, validationResult } = require('express-validator');

require('../../passport')();

const auth = require('../../middleware/auth');

const User = require('../../models/Users');

// @route    POST api/auth/email/register
// @desc     Register User via Email
// @access   Public

router.post(
	'/email/register',
	[
		check('name', 'Name is required')
			.not()
			.isEmpty(),
		check('email', 'Please Include a Valid email').isEmail(),
		check(
			'password',
			'Please Enter a Password with 6 or more characters'
		).isLength({ min: 6 })
	],
	async (req, res) => {
		const errors = validationResult(req);

		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}

		const { name, email, password } = req.body;

		try {
			// see if user exist
			let user = await User.findOne({ email: email });

			//see if user exists
			if (user) {
				return res
					.status(400)
					.json({ errors: [{ msg: 'User Already Exists' }] });
			}

			user = new User({
				name,
				email,
				password
			});

			//encrypt the pasword
			const salt = await bcrypt.genSalt(10);

			user.password = await bcrypt.hash(password, salt);

			await user.save();

			//return jsonwebtekon
			const payload = {
				user: {
					id: user.id
				}
			};

			jwt.sign(
				payload,
				config.get('jwtSecret'),
				{ expiresIn: 360000 },
				(err, token) => {
					if (err) throw err;
					return res.json({ token });
				}
			);
		} catch (err) {
			console.error(err.message);
			res.status(500).send('Server Error');
		}
	}
);

// @route    POST api/auth/email
// @desc     Login User  Using Email
// @access   Public

router.post(
	'/email',
	[
		check('email', 'Please Include a Valid email').isEmail(),
		check('password', 'Password is required').exists()
	],
	async (req, res) => {
		const errors = validationResult(req);

		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}

		const { email, password } = req.body;

		try {
			// see if user exist
			let user = await User.findOne({ email: email });

			//see if user not founded
			if (!user) {
				return res
					.status(400)
					.json({ errors: [{ msg: 'Invalid Credentials' }] });
			}

			const isMatch = await bcrypt.compare(password, user.password);

			if (!isMatch) {
				return res
					.status(400)
					.json({ errors: [{ msg: 'Invalid Credentials' }] });
			}

			//return jsonwebtekon
			const payload = {
				user: {
					id: user.id
				}
			};

			jwt.sign(
				payload,
				config.get('jwtSecret'),
				{ expiresIn: 360000 },
				(err, token) => {
					if (err) throw err;
					return res.json({ token });
				}
			);
		} catch (err) {
			console.error(err.message);
			res.status(500).send('Server Error');
		}
	}
);

// @route    GET api/Auth/facebook
// @desc     Register And Login Using Facebook
// @access   Public

router.get(
	'/facebook',
	passport.authenticate('facebook', { scope: ['email'] }),
	function(req, res) {}
);
router.get(
	'/facebook/callback',
	passport.authenticate('facebook', { failureRedirect: '/' }),
	function(req, res) {
		req.app.set('user', res.req.user);
		res.redirect('/api/auth/facebook/accessToken');
	}
);
router.get('/facebook/accessToken', (req, res) => {
	const UserData = req.app.get('user');

	const payload = {
		user: {
			id: UserData.id
		}
	};

	jwt.sign(
		payload,
		config.get('jwtSecret'),
		{ expiresIn: 360000 },
		(err, token) => {
			if (err) throw err;
			return res.json({ access_token: token });
		}
	);
});

// @route    GET api/Auth/google
// @desc     Register And Login Using Google
// @access   Public

router.get(
	'/google',
	passport.authenticate('google', {
		scope: ['email', 'profile']
	}),
	function(req, res) {}
);
router.get(
	'/google/callback',
	passport.authenticate('google', { failureRedirect: '/' }),
	function(req, res) {
		req.app.set('user', res.req.user);
		res.redirect('/api/auth/google/accessToken');
	}
);
router.get('/google/accessToken', (req, res) => {
	const UserData = req.app.get('user');

	const payload = {
		user: {
			id: UserData.id
		}
	};

	jwt.sign(
		payload,
		config.get('jwtSecret'),
		{ expiresIn: 360000 },
		(err, token) => {
			if (err) throw err;
			return res.json({ access_token: token });
		}
	);
});

module.exports = router;
