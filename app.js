const express = require("express");
const { connection } = require("./config");
const UserModel = require("./models/User.model");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const app = express();
app.use(express.json());

app.post("/signup", async (req, res) => {
  let { email, password, age } = req.body;
  await bcrypt.hash(password, 8, function (err, hash) {
    if (err) {
      return res.send("Signup Faild please try again");
    }
    const user = new UserModel({ email, password: hash, age });
    user.save(); // Creating new user and saving it into database
    return res.send("Signup successfull");
  });
});

app.post("/login", async (req, res) => {
  let { email, password } = req.body;
  const user = await UserModel.findOne({ email });
  if (!user) {
    return res.send("Invalid Credentials. Please try again");
  }
  const hashed_password = user.password;
  await bcrypt.compare(password, hashed_password, function (err, result) {
    if (err) {
      return res.send("Please Try Again later");
    }
    if (result) {
      const token = jwt.sign(
        { email: user.email, age: user.age, _id: user._id },
        "secret"
      );
      return res.send({ message: "Login successfull", token: token });
    } else {
      return res.send("Invalid Credentials. Please try again");
    }
  });
});

app.get("/profile/:id", async (req, res) => {
  const id = req.params.id;
  const user_token = req.headers.authorization.split(" ")[1];

  jwt.verify(user_token, "secret", function (err, decoded) {
    if (err) {
      return res.send("Login Again");
    }
  });

  try {
    const user = await UserModel.find({ _id: id });
    return res.send(user);
  } catch {
    return res.send("not found");
  }
});

app.listen(8080, async () => {
  try {
    await connection;
    console.log("Connected to Server");
  } catch {
    console.log("connection error");
  }
  console.log("Server running at http://localhost:8080");
});
