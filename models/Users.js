const mongoose = require('mongoose');
const UserSchema = new mongoose.Schema({
	name: {
		type: String,
		required: true
	},
	email: {
		type: String,
		required: true,
		unique: true
	},
	password: {
		type: String
	},
	date: {
		type: Date,
		default: Date.now
	},
	userInfo: {
		id_user: {
			type: mongoose.SchemaTypes.ObjectId,
			ref: 'user'
		},
		login_type: {
			type: String
		},
		facebook_id: {
			type: String
		},
		token: {
			type: String
		},
		date: {
			type: Date,
			default: Date.now
		}
	}
});

module.exports = User = mongoose.model('user', UserSchema);
