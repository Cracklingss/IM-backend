const express = require("express");
const router = express.Router();
const { login, logout, changePass, forgotPass, changeProfile, getCookies, onBoarding }  = require("./models");

router.post("/login", login);
router.post("/logout", logout);
router.post("/change-password", changePass);
router.post("/forgot-password", forgotPass);
router.put("/profile", changeProfile);
router.get("/me", getCookies);
router.put("/onboarding", onBoarding);

module.exports = router;