const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const userSchema = new Schema({
  name: {
    type: String,
    required: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  telephone: {
    type: String,
    required: false,
  },
  emailAuthenticated: {
    type: Boolean,
    required: true,
    default: false,
  },
});

module.exports = mongoose.model("user", userSchema);
