const express = require("express");
const app = express();
const port = 3000;

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const axios = require("axios");
require("dotenv").config();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User schema and model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  preferences: {
    categories: { type: [String], default: [] },
    languages: { type: [String], default: [] },
  },
});

const User = mongoose.model("User", userSchema);

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user; // Store user info in request
    next(); // Proceed to the next middleware or route
  });
};

// Register endpoint
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create and save the new user
  const user = new User({ username, password: hashedPassword });
  await user.save();

  res.status(201).json({ message: "User registered successfully" });
});

// Login endpoint
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Find the user
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(400).json({ message: "Invalid username or password" });
  }

  // Compare the password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ message: "Invalid username or password" });
  }

  // Generate a JWT token
  const token = jwt.sign(
    { id: user._id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.status(200).json({ token });
});

// Get user preferences
app.get("/preferences", authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id).select("preferences");
  if (!user) return res.sendStatus(404); // Not Found
  res.status(200).json(user.preferences);
});

// Update user preferences
app.put("/preferences", authenticateToken, async (req, res) => {
  const { categories, languages } = req.body;

  // Validate input
  if (!Array.isArray(categories) || !Array.isArray(languages)) {
    return res
      .status(400)
      .json({ message: "Categories and languages must be arrays" });
  }

  const user = await User.findByIdAndUpdate(
    req.user.id,
    { preferences: { categories, languages } },
    { new: true } // Return the updated document
  );

  if (!user) return res.sendStatus(404); // Not Found
  res.status(200).json(user.preferences);
});

app.get("/news", authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id).select("preferences");
  if (!user) return res.sendStatus(404); // Not Found

  const { categories, languages } = user.preferences;

  // Prepare the query parameters for the news API
  const queryParams = {
    apiKey: process.env.NEWS_API_KEY, // Your News API Key
    category: categories.join(","), // Join categories for the API
    language: languages.join(","), // Join languages for the API
    pageSize: 10, // Limit the number of articles
  };

  try {
    const response = await axios.get("https://newsapi.org/v2/top-headlines", {
      params: queryParams,
    });
    const articles = response.data.articles;

    if (articles.length === 0) {
      return res.status(204).json({ message: "No articles found" }); // No Content
    }

    res.status(200).json(articles);
  } catch (error) {
    console.error("Error fetching news:", error.message);
    if (error.response) {
      return res.status(error.response.status).json({
        message: error.response.data.message || "Error fetching news",
      });
    }
    res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(port, (err) => {
  if (err) {
    return console.log("Something bad happened", err);
  }
  console.log(`Server is listening on ${port}`);
});

module.exports = app;
