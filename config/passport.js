const passport = require('passport');
const LoacalStrategy = require('passport-local').Strategy;
const User = require('../modals/user');

// Passport.serializeUser
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// passport.deserializeUser
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// passport.use(...)
passport.use('local', new LoacalStrategy({
  usernameField: 'email',
  passwordField: 'password',
  passReqToCallback: false
}, async (email, password, done) => {
  try {
    // Check if email already exist
    const user = await User.findOne({ email });
    if (!user) {
      return done(null, false, { message: 'Email or password is invalid' });
    }

    // Check if the password is correct
    const isValid = await User.comparePasswords(password, user.password);

    if (!isValid) {
      return done(null, false, { message: 'Unknown Password' });
    }

    // Check if the account has been verified
    if (!user.active) {
      return done(null, false, { message: 'You need to verify email first' });
    }
    return done(null, user);
  } catch (error) {
    return done(error, false);
  }
}));

