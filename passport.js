const config = require('config');
const passport = require('passport');
const User = require('./models/Users');
const FacebookStrategy = require('passport-facebook').Strategy;
const GoogleStrategy = require('passport-google-oauth2').Strategy;

// config
module.exports = function() {
	passport.use(
		new FacebookStrategy(
			{
				clientID: config.get('clientID'),
				clientSecret: config.get('clientSecret'),
				callbackURL: config.get('callbackURL'),
				profileFields: ['id', 'emails', 'displayName']
			},
			function(accessToken, refreshToken, profile, done) {
				User.findOne({ 'userInfo.social_id': profile.id }, async function(
					err,
					user
				) {
					if (err) {
						return done(err);
					}
					if (!err && user !== null) {
						done(null, user);
					} else {
						const userInfo = {};
						userInfo.social_id = profile.id;
						userInfo.token = accessToken;
						userInfo.login_type = 'fb';
						const email = profile.emails[0].value;

						user = new User({
							name: profile.displayName,
							email,
							userInfo
						});

						await user.save();

						done(null, user);
					}
				});
			}
		)
	);
	passport.use(
		new GoogleStrategy(
			{
				clientID: config.get('clientIDGoogle'),
				clientSecret: config.get('clientSecretGoogle'),
				callbackURL: config.get('callbackGoogleUrl'),
				passReqToCallback: true,
				profileFields: ['id', 'emails', 'displayName', 'openid']
			},
			function(request, accessToken, refreshToken, profile, done) {
				User.findOne({ 'userInfo.social_id': profile.id }, async function(
					err,
					user
				) {
					if (err) {
						return done(err);
					}
					if (!err && user !== null) {
						done(null, user);
					} else {
						const userInfo = {};
						userInfo.social_id = profile.id;
						userInfo.token = accessToken;
						userInfo.login_type = 'google';
						const email = profile.email;
						user = new User({
							name: profile.displayName,
							email,
							userInfo
						});

						await user.save();
						console.log(user);
						done(null, user);
					}
				});
			}
		)
	);
};
