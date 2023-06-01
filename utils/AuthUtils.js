const validator = require("validator");

const cleanUpAndValidate = ({ name, email, password, username }) => {
  return new Promise((resolve, reject) => {
    if (!email || !password || !name || !username) {
      reject("Missing Credentials.");
    }
    if (typeof email !== "string") {
      reject("Invalid Email");
    }

    if (typeof username !== "string") {
      reject("Invalid Username");
    }
    if (typeof password !== "string") {
      reject("Invalid Password");
    }

    if (username.length <= 2 || username.length > 50) {
      reject("Username length should be 3-50");
    }

    if (password.length <= 2 || password.length > 25) {
      reject("Password length should be 3-25");
    }

    if (!validator.isEmail(email)) {
      reject("Invalid email format");
    }

    resolve();
  });
};
module.exports = { cleanUpAndValidate };
