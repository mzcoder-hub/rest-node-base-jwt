const express = require('express');
const connectDB = require('./config/db');
const config = require('config');
const passport = require('passport');
const cors = require('cors');
const app = express();

//connect Database
connectDB();

//cors
app.use(cors());
app.use(passport.initialize());
app.use(passport.session());

// serialize and deserialize
passport.serializeUser(function(user, done) {
	done(null, user);
});
passport.deserializeUser(function(obj, done) {
	done(null, obj);
});

// init Middleware
app.use(express.json({ extended: false }));

// Define Routes

app.use('/api/users', require('./routes/api/User'));
app.use('/api/auth', require('./routes/api/auth'));

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
