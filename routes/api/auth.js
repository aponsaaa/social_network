const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const auth = require('../../middleware/auth');
const jwt = require('jsonwebtoken');
const config = require('config');
const {
    check,
    validationResult
} = require('express-validator');

const User = require('../../models/User')
// @route   GET api/auth
// @desc    Test route
// @access  Public
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
});

// @route   GET api/auth
// @desc    Authenticate user & get token
// @access  Public

router.post('/', [
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Please enter a password with 6 more characters').exists()
    ],
    async (req, res) => {
        // console.log(req.body);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array()
            })
        }

        const {
            email,
            password
        } = req.body;

        try {
            // See if user exists
            let user = await User.findOne({
                email
            });

            if (!user) {
                return res.status(400).json({
                    errors: [{
                        msg: "Invalid Credentials"
                    }]
                });
            }

            // Password Verification
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(400).json({
                    errors: [{
                        msg: "Invalid Credentials"
                    }]
                });
            }

            const payload = {
                user: {
                    id: user.id
                }
            }
            jwt.sign(
                payload, config.get('jwtSecret'), {
                    expiresIn: 36000
                }, (error, token) => {
                    if (error) throw error;
                    res.json({
                        token
                    });
                }
            );
            // res.send('User registered');

        } catch (error) {
            console.error(error.message);
            res.status(500).send('Server error');

        }
    });


module.exports = router;