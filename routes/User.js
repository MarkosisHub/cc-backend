const router = require('express').Router()
const userCtrl = require('../controllers/User')
const { protect, admin } = require("../middleware/auth");

//for protect routes you need token to attach in headers

router.post('/register', userCtrl.register)
router.post('/login', userCtrl.login)
router.post('/logout', userCtrl.logout)
router.post('/refresh_token', userCtrl.getAccessToken)
router.post('/forgot',protect, userCtrl.forgotPassword)
router.post('/reset', protect, userCtrl.resetPassword)
router.get('/user_info/:id',protect, userCtrl.getUser)
router.get('/all_user', protect, admin, userCtrl.getUsers)
router.patch('/update_user', protect, userCtrl.updateUser)
router.patch('/update_role/:id', protect, admin, userCtrl.updateUsersRole)
router.delete('/delete_user/:id', protect, admin, userCtrl.deleteUser)

// Social Login
router.post('/google_login', userCtrl.googleLogin)
router.post('/facebook_login', userCtrl.facebookLogin)

module.exports = router