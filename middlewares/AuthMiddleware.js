const isAuth = (req, res, next) => {
  if (req.session.isAuth) {
    console.log("Authmiddleware");
    next();
  } else {
    return res.send({
      status: 401,
      message: "Invalid session, Please login again",
    });
  }
};

module.exports = { isAuth };
