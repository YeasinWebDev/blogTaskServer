const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const app = express();
const PORT = process.env.PORT || 5000;

app.use(express());
app.use(
  cors({
    origin: ["http://localhost:5173", "https://blogs-task-client.vercel.app", "https://blog-task-server.vercel.app"],
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
  secure: process.env.NODE_ENV === "production",
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
    // await client.connect();

    const db = client.db("blogs");
    const usersCollection = db.collection("users");
    const blogsCollection = db.collection("blogs");

    // register
    app.post("/signUp", async (req, res) => {
      const { email, password, name } = req.body;

      const userExists = await usersCollection.findOne({ email });
      if (userExists) {
        return res.status(400).send({ message: "User already exists" });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = { email, password: hashedPassword, name };
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

      res.send({
        success: true,
        message: "Logged in successfully",
        user,
        token,
      });
    });

    // all blogs
    app.get("/blogs", async (req, res) => {
      const blogs = await blogsCollection.find().toArray();
      res.send(blogs);
    });

    app.post("/addblogs", async (req, res) => {
      const blogs = req.body;
      console.log(blogs);
      const result = await blogsCollection.insertOne(blogs);
      res.send(result);
    });

    app.delete("/delete/:id", async (req, res) => {
      const { id } = req.params;
      const result = await blogsCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    });
    app.put("/blogsUpdate/:id", async (req, res) => {
      const { id } = req.params;
      const updatedBlog = req.body;
      console.log(id)
      const result = await blogsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            name: updatedBlog.name,
            category: updatedBlog.category,
            description: updatedBlog.description,
          },
        }
      );
      res.send(result);
    });

    // await client.db("admin").command({ ping: 1 });
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
