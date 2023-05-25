const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

//Create an instance of the Express application and configure it to use body-parser
const app = express();
app.use(bodyParser.json());

//Set up an in-memory data store to store user information
let users = [];

//User Registration (Sign-up):
app.post("/signup", (req, res) => {
  const { email, password } = req.body;
  // Check if the email is already registered
  const existingUser = users.find((user) => user.email === email);
  if (existingUser) {
    return res.status(409).json({ error: "Email already exists" });
  }
  // Hash the password
  const saltRounds = 10;
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      return res.status(500).json({ error: "Internal server error" });
    }
    // Create a new user
    const newUser = { email, password: hash };
    users.push(newUser);
    res.status(201).json({ message: "User registered successfully" });
  });
});

//User Authentication (Login)
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  // Find the user by email
  const user = users.find((user) => user.email === email);
  if (!user) {
    return res.status(401).json({ error: "Invalid email or password" });
  }
  // Compare the password
  bcrypt.compare(password, user.password, (err, result) => {
    if (err || !result) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    // Generate a JWT
    const token = jwt.sign({ email: user.email }, "your_secret_key");
    res.status(200).json({ token });
  });
});

//Protecting a Route/Endpoint:
app.get("/protected", verifyToken, (req, res) => {
  res.json({ message: "Protected endpoint accessed successfully" });
});

function verifyToken(req, res, next) {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  jwt.verify(token, "your_secret_key", (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    req.user = decoded;
    next();
  });
}

// the server
const port = 3000;
app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
