const express = require("express");
const router = express.Router();
const { ContactUs } = require("../controllers/ContactUs");

router.route("/").post(ContactUs);

module.exports = router;
