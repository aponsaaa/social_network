const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const {
    check,
    validationResult
} = require('express-validator');

const User = require('../../models/User');
const {
    JsonWebTokenError
} = require('jsonwebtoken');

// @route   GET api/users
// @desc    Register User
// @access  Public
router.post('/', [
        check('name', 'Name is required').not().isEmpty(),
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Please enter a password with 6 more characters').isLength({
            min: 6
        })
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
            name,
            email,
            password
        } = req.body;

        try {
            // See if user exists
            let user = await User.findOne({
                email
            });

            if (user) {
                return res.status(400).json({
                    errors: [{
                        msg: "User already exists"
                    }]
                });
            }

            // Get users gravatar
            const avatar = gravatar.url(email, {
                s: '200',
                r: 'pg',
                d: 'mm'
            })

            user = new User({
                name,
                email,
                avatar,
                password
            });

            // Encrypt password
            const salt = await bcrypt.genSalt(10);

            user.password = await bcrypt.hash(password, salt);

            await user.save();

            // Return jsonwebtoken

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