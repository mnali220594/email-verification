const express = require('express');
const router = express.Router();
const Joi = require('joi');
const User = require('../modals/user');
const passport = require('passport');
const randomstring = require('randomstring');
const mailer = require('../misc/mailer');

// Validation Schema
const userSchema = Joi.object().keys({
  email: Joi.string().email().required(),
  username: Joi.string().required(),
  password: Joi.string().regex(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/).required(),
  confirmationPassword: Joi.any().valid(Joi.ref('password')).required()
});

// Authorization
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    // Good
    return next();
  } else {
    req.flash('error', 'Sorry, but you must be registered first!');
    res.redirect('/');
  }
}

const isNotAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    req.flash('error', 'Sorry, but you are already logged in!');
    res.redirect('/');
    return next();
  } else {
    return next();
  }
}

router.route('/register')
  .get(isNotAuthenticated, (req, res) => {
    res.render('register');
  })
  .post(async (req, res, next) => {
    try {
      const result = Joi.validate(req.body, userSchema);
      console.log('result', result);

      if (result.error) {
        req.flash('error', 'Data is not valid. Please try again.');
        res.redirect('/users/register');
        return;
      }

      // Checking if email is already taken
      const user = await User.findOne({ 'email': result.value.email });
      if (user) {
        req.flash('error', 'Email is already in use');
        res.redirect('/users/register');
        return;
      }

      // Hash the password
      const hash = await User.hashPassword(result.value.password);

      // Generate secret token
      const secretToken = randomstring.generate();
      result.value.secretToken = secretToken;

      // Flag the account as inactive
      result.value.active = false;

      // Save user to DB
      delete result.value.confirmationPassword;
      result.value.password = hash;
      // console.log('new values', result.value);

      const newUser = await new User(result.value);
      console.log('newUser', newUser);
      await newUser.save();

      // Compose an email
      const html = `Hi there, <br/>
      Thank you for registering!
      <br/><br/>
      Plesea verify your email by typing the following token: 
      <br/>
      Token: <b>${secretToken}</b>
      <br/>
      On the following page: <a href="http://localhost:5000/users/verify">http://localhost:5000/users/verify</a>
      <br/><br/>
      Have a pleasent day!`;

      // Send the email
      await mailer.sendMail('admin@alisite.com', result.value.email, 'Please verify your email!', html);
      req.flash('success', 'Please check your email');
      res.redirect('/users/login');
    } catch (error) {
      next(error);
    }

  });

router.route('/login')
  .get(isNotAuthenticated, (req, res) => {
    res.render('login');
  })
  .post(passport.authenticate('local', {
    successRedirect: '/users/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true
  }));

router.route('/dashboard')
  .get(isAuthenticated, (req, res) => {
    res.render('dashboard', {
      username: req.user.username
    });
  });

router.route('/verify')
  .get(isNotAuthenticated, (req, res) => {
    res.render('verify');
  });

router.route('/verify')
  .post(async (req, res, next) => {
    try {
      const secretToken = req.body.secretToken;

      // Find the account that matches the secret token
      const user = await User.findOne({ secretToken: secretToken });
      if (!user) {
        console.log(user)
        req.flash('error', 'No user found.');
        res.redirect('/users/verify');
        return;
      }

      user.active = true;
      // user.secretToken = '';
      await user.save();

      req.flash('success', 'Thank you! Now you may login.');
      res.redirect('/users/login');
    } catch (err) {
      console.log(err);
      next(err);
    }
  });


router.route('/logout')
  .get(isAuthenticated, (req, res) => {
    req.logout();
    req.flash('success', 'Successfully logged out. Hope to see you soon');
    res.redirect('/');
  })

module.exports = router;