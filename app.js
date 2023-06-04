const express = require("express");
const clc = require("cli-color");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const validator = require("validator");
const session = require("express-session");
const mongoDbSession = require("connect-mongodb-session")(session);
const { isAuth } = require("./middlewares/AuthMiddleware");
const { rateLimiting } = require("./middlewares/rateLimiting");
const jwt = require("jsonwebtoken");

// file imports
const {
  cleanUpAndValidate,
  generateJWTToken,
  sendVerificationToken,
} = require("./utils/AuthUtils");
const userSchema = require("./userSchema");
const BookModel = require("./models/BookModel");

// variables
PORT = process.env.PORT || 8000;
const app = express();
const MONGO_URI = `mongodb+srv://emailjyotisingh13:BYlqE2fM976e745E@cluster0.3d1lybe.mongodb.net/marchToDoApp`;
const saltRound = 11;

app.set("view engine", "ejs");

// DB connection
mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log(clc.green.bold.underline("MongoDB connected"));
  })
  .catch((err) => {
    console.log(clc.red.bold(err));
  });

// middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

const store = new mongoDbSession({
  uri: MONGO_URI,
  collection: "sessions",
});

app.use(
  session({
    secret: "This is Book app, we dont love coding",
    resave: false,
    saveUninitialized: false,
    store: store,
  })
);

// routes
app.get("/", (req, res) => {
  return res.send("This is your library management app.");
});

app.get("/registration", (req, res) => {
  return res.render("register");
});

app.get("/login", (req, res) => {
  return res.render("login");
});

// MVC STURCTURE
app.post("/register", async (req, res) => {
  console.log(req.body);
  const { name, email, password, username } = req.body;

  //data validation
  try {
    await cleanUpAndValidate({ name, email, password, username });

    //check if the user exits

    const userExistEmail = await userSchema.findOne({ email });

    console.log(userExistEmail);
    if (userExistEmail) {
      return res.send({
        status: 400,
        message: "Email Already exits",
      });
    }

    const userExistUsername = await userSchema.findOne({ username });

    if (userExistUsername) {
      return res.send({
        status: 400,
        message: "Username Already exits",
      });
    }

    //hash the password using bcypt
    const hashPassword = await bcrypt.hash(password, saltRound);

    const user = new userSchema({
      name: name,
      email: email,
      password: hashPassword,
      username: username,
    });

    try {
      const userDb = await user.save(); //create a user in DB
      console.log(userDb);
      // token generate
      const verificationToken = generateJWTToken(email);
      console.log(verificationToken);
      // send mai function
      sendVerificationToken({ email, verificationToken });
      console.log(userDb);
      return res.send({
        status: 200,
        message:
          "Registration successfull, Link has been sent to your mail id. Please verify before login.",
      });
    } catch (error) {
      return res.send({
        status: 500,
        message: "Database error",
        error: error,
      });
    }
  } catch (error) {
    console.log(error);
    return res.send({
      status: 400,
      message: "Data Invalid",
      error: error,
    });
  }
});

app.get("/api/:token", (req, res) => {
  console.log(req.params);
  const token = req.params.token;
  const SECRET_KEY = "This is march nodejs class";

  jwt.verify(token, SECRET_KEY, async (err, decoded) => {
    try {
      const userDb = await userSchema.findOneAndUpdate(
        { email: decoded },
        { emailAuthenticated: true }
      );
      console.log(userDb);
      return res.status(200).redirect("/login");
    } catch (error) {
      res.send({
        status: 500,
        message: "database error",
        error: error,
      });
    }
  });
});

app.post("/login", async (req, res) => {
  //validate the data
  console.log(req.body);
  const { loginId, password } = req.body;

  if (!loginId || !password) {
    return res.send({
      status: 400,
      message: "missing credentials",
    });
  }

  if (typeof loginId !== "string" || typeof password !== "string") {
    return res.send({
      status: 400,
      message: "Invalid data format",
    });
  }

  //identify the email and search in database

  try {
    let userDb;
    if (validator.isEmail(loginId)) {
      userDb = await userSchema.findOne({ email: loginId });
    } else {
      userDb = await userSchema.findOne({ username: email });
    }

    if (!userDb) {
      return res.send({
        status: 400,
        message: "User not found, Please register first",
      });
    }

    if (userDb.emailAuthenticated === false) {
      return res.send({
        status: 400,
        message: "Email not authenticated",
      });
    }

    //password compare bcrypt.compare
    const isMatch = await bcrypt.compare(password, userDb.password);

    if (!isMatch) {
      return res.send({
        status: 400,
        message: "Password Does not match",
      });
    }

    //Add session base auth sys
    console.log(req.session);
    req.session.isAuth = true;
    req.session.user = {
      username: userDb.username,
      email: userDb.email,
      userId: userDb._id,
    };

    return res.redirect("/dashboard");
  } catch (error) {
    console.log(error);
    return res.send({
      status: 500,
      message: "Database error",
      error: error,
    });
  }
});

//Change password route
app.get("/forgotPasswordPage", (req, res) => {
  res.render("forgotPasswordPage");
});

//resend Verification Mail
app.get("/resendVerificationMail", (req, res) => {
  res.render("resendVerificationMail");
});

app.get("/dashboard", isAuth, async (req, res) => {
  return res.render("dashboard");
});

//logout api's
app.post("/logout", isAuth, (req, res) => {
  console.log(req.session);
  req.session.destroy((err) => {
    if (err) throw err;

    return res.redirect("/login");
  });
});

app.post("/resendVerificationMail", async (req, res) => {
  console.log(req.body);
  const { loginId } = req.body;
  if (validator.isEmail(loginId)) {
    //here i create token for 2fa
    const token = generateJWTToken(loginId);
    // console.log(token);
    try {
      sendVerificationToken({ loginId, token });
      return res.status(200).redirect("/login");
    } catch (error) {
      console.log(error);
      return res.send({
        status: 400,
        message: "error in resend varification mail",
        error: error,
      });
    }
  } else {
    return res.send(
      `<center><h2>!!<br>(-----Please provide a valid email address-----)</h2></center>`
    );
  }
});

app.post("/forgotPassword", async (req, res) => {
  
});

app.post("/logout_from_all_devices", isAuth, async (req, res) => {
  const username = req.session.user.username;

  //create a session schema
  const Schema = mongoose.Schema;
  const sessionSchema = new Schema({ _id: String }, { strict: false });
  const sessionModel = mongoose.model("session", sessionSchema);

  try {
    const deletionCount = await sessionModel.deleteMany({
      "session.user.username": username,
    });
    console.log(deletionCount);
    return res.send({
      status: 200,
      message: "Logout from all devices successfully",
    });
  } catch (error) {
    return res.send({
      status: 500,
      message: "Logout Failed",
      error: error,
    });
  }
});

app.post("/create-item", isAuth, rateLimiting, async (req, res) => {
  console.log(req.session);
  console.log(req.body);

  const { bookTitle, bookAuthor, bookPrice, bookCategory } = req.body.book;
  console.log(bookTitle);

  // Data validation
  if (!bookTitle) {
    return res.send({
      status: 400,
      message: "Book is empty",
    });
  } else if (typeof bookTitle !== "string") {
    return res.send({
      status: 400,
      message: "Invalid book format",
    });
  } else if (bookTitle.length > 100) {
    return res.send({
      status: 400,
      message:
        "Invalid book length, it should be in the range of 3 to 100 characters.",
    });
  }
  // initialize book schema and store it in DB
  const book = new BookModel({
    bookTitle: bookTitle,
    bookAuthor: bookAuthor,
    bookPrice: bookPrice,
    bookCategory: bookCategory,
    username: req.session.user.username,
  });
  const bookDb = await book.save();
  try {
    const bookDb = await book.save();
    console.log(book);
    return res.send({
      status: 201,
      message: "Book created successfully",
      data: bookDb,
    });
  } catch (error) {
    return res.send({
      status: 500,
      message: "Database error",
      error: error,
    });
  }
});

app.post("/edit-item", isAuth, async (req, res) => {
  console.log(req.body);
  // const { id, newData } = req.body;
  const { id, newBookTitle, newBookAuthor, newBookPrice, newBookCategory } =
    req.body;

  console.log(newBookTitle);
  // if (!id || !bookTitle) {
  //   return res.send({
  //     status: 400,
  //     message: "Missing credentials",
  //   });
  // }
  // if (typeof bookTitle !== "string") {
  //   return res.send({
  //     status: 400,
  //     message: "Invalid book format",
  //   });
  // }
  // if (bookTitle.length > 100) {
  //   return res.send({
  //     message: "Book is too long, should be less than 100 char.",
  //   });
  // }

  try {
    const bookDb = await BookModel.findOneAndUpdate(
      { _id: id },
      {
        bookTitle: newBookTitle,
        bookAuthor: newBookAuthor,
        bookPrice: newBookPrice,
        bookCategory: newBookCategory,
      }
    );
    console.log(bookDb);
    return res.send({
      status: 200,
      message: "Book updated successfully",
      data: bookDb,
    });
  } catch (error) {
    return res.send({
      status: 500,
      message: "Database error",
      error: error,
    });
  }
});

app.post("/delete-item", isAuth, async (req, res) => {
  console.log(req.body);
  const id = req.body.id;
  // console.log(req.body);
  // data validation
  if (!id) {
    return res.send({
      status: 400,
      message: "Missing credentials",
    });
  }

  try {
    const bookDb = await BookModel.findOneAndDelete({ _id: id });
    console.log(bookDb);
    return res.send({
      status: 200,
      message: "Book deleted successfully",
      data: bookDb,
    });
  } catch (error) {
    return res.send({
      status: 500,
      message: "Database error",
      error: error,
    });
  }
});

// app.get("/read-item", async (req, res) => {
//   console.log(req.session.user.username);
//   const user_name = req.session.user.username;
//   try {
//     const books = await BookModel.find({ username: user_name });

//     if (books.length === 0)
//       return res.send({
//         status: 400,
//         message: "Book is empty, Please create some.",
//       });

//     return res.send({
//       status: 200,
//       message: "Read Success",
//       data: books,
//     });
//   } catch (error) {
//     return res.send({
//       status: 500,
//       message: "Database error",
//       error: error,
//     });
//   }
// });

// Pagination
// Pagination_dashboard?skip=10

app.get("/pagination_dashboard", isAuth, async (req, res) => {
  const skip = req.query.skip || 0; //client
  const LIMIT = 5; //backend

  const user_name = req.session.user.username;

  try {
    const books = await BookModel.aggregate([
      // match, pagination-skip-limit
      { $match: { username: user_name } },
      {
        $facet: {
          data: [{ $skip: parseInt(skip) }, { $limit: LIMIT }],
        },
      },
    ]);
    // console.log(books[0].data);
    return res.send({
      status: 200,
      message: "Read success",
      data: books[0].data,
    });
  } catch (error) {
    return res.send({
      status: 500,
      message: "Database error",
      error: error,
    });
  }
});

app.listen(PORT, () => {
  console.log(clc.yellow.bold(`Server is running.`));
  console.log(clc.yellow.bold.underline(`http://localhost:${PORT}`));
});

/* create server and mongodb-connection
Registration page
register.js
register a user in DB
Login page
Dashboard

Register Page
Registration API

Login Page
Login API

Session base authentication

Dashboard page
Logout
Logout from all devices

book API
Create
Edit
Delete
Read
Show the book on dashboard page

Dashboard
Browser.js
Axios - GET and POST CRUD (client-side)
read component

API Optimisation:-
Pagination of API's
Ratelimiting

MVC(Models, Views, Controller)
Jsx
EJS
Deploy
*/
