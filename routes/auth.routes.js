const router = require("express").Router();
const bcryptjs = require("bcryptjs");
const User = require("../models/User.model");

router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", async (req, res, next) => {
  const userInput = req.body;
  if (!userInput.username) {
    res.render("auth/signup", { errorMessage: "Please enter username" });
    return;
  } else if (userInput.password?.length < 8) {
    res.render("auth/signup", {
      errorMessage: "Password should be 8 digit long",
    });
    return;
  }
  try {
    const userExist = await User.findOne({ username: userInput.username });
    if (userExist) {
      res.render("auth/signup", { errorMessage: "Username already exist" });
      return;
    }
    bcryptjs.genSalt(10, async function (err, salt) {
      bcryptjs.hash(userInput.password, salt, async function (err, hash) {
        const newUser = await User.create({
          username: userInput.username,
          password: hash,
        });
        req.session.user = newUser;
        res.redirect("/");
      });
    });
  } catch (err) {
    console.log({ err });
    res.render("auth/signup");
  }
});

module.exports = router;
