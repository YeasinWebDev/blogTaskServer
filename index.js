const { MongoClient, ServerApiVersion } = require("mongodb");
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
require("dotenv").config();
const app = express();
const PORT = process.env.PORT || 5000;

app.use(express());
app.use(
    cors({
      origin: [
        "http://localhost:5173"
      ],
      credentials: true,
    })
  );
app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  res.send("CRUD IS RUNNER");
});

const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production" ,
    sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
  };

const username = process.env.DB_USERNAME;
const password = process.env.DB_PASSWORD;

const uri = `mongodb+srv://${username}:${password}@cluster0.be4xnde.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const verifyTOken = (req, res, next) => {
  const token = req?.cookies?.token;
  if (!token) {
    return res.send({ massage: "unauthorized access" });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN, (err, decoded) => {
    if (err) {
      return res.send({ massage: "unauthorized access" });
    }
    req.user = decoded;
    next();
  });
};

async function run() {
  try {

    await client.connect();
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN, {
        expiresIn: "1h",
      });
      res.cookie("token", token, cookieOptions).send({ success: true });
    });

    //clearing Token
    app.post("/logout", async (req, res) => {
      const user = req.body;
      res
        .clearCookie("token", { ...cookieOptions, maxAge: 0 })
        .send({ success: true });
    });

    const db = client.db("blogs");
    const usersCollection = db.collection("users");

    // register
    app.post("/signUp", async (req, res) => {
      const { email, password ,name } = req.body;

      const userExists = await usersCollection.findOne({ email });
      if (userExists) {
        return res.status(400).send({ message: "User already exists" });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = { email, password: hashedPassword,name };
      await usersCollection.insertOne(newUser);

      res.send({ success: true, message: "User registered successfully" });
    });

    // User Login
    app.post("/login", async (req, res) => {
      const { email, password } = req.body;
      const user = await usersCollection.findOne({ email });

      if (!user) {
        return res.status(400).send({ message: "User not found" });
      }

      // Compare password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).send({ message: "Invalid credentials" });
      }

      // Create JWT
      const token = jwt.sign({ email }, process.env.ACCESS_TOKEN, {
        expiresIn: "1h",
      });

      // Set the JWT as a cookie
      res
        .cookie("token", token, cookieOptions)
        .send({ success: true, message: "Logged in successfully" ,user});
    });

    // Logout - Clear the JWT token
    app.post("/logout", async (req, res) => {
      res
        .clearCookie("token", { ...cookieOptions, maxAge: 0 })
        .send({ success: true, message: "Logged out successfully" });
    });

    
    await client.db("admin").command({ ping: 1 });
    // console.log(
    //   "Pinged your deployment. You successfully connected to MongoDB!"
    // );
  } finally {
    // await client.close();
  }
}
run().catch(console.dir);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

