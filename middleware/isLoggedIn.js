const isLoggedIn = (req, res, next) => {
  console.log("req.session.user", req.session.user);
  if (!req.session.user) {
    return res.redirect("/auth/login");
  }
  next();
};

module.exports = isLoggedIn;
