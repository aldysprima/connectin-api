const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
dotenv.config();

const database = require("./config");

// Define Main App
const app = express();

// Open Access to public folder
app.use(express.static("public"));

// Config Middlewares
app.use(express.json());
app.use(cors({ exposedHeaders: ["UID", "Auth-Token"] }));

// test database connection
database.connect((error) => {
  if (error) {
    console.log("error, ", error);
  }
  console.log(`database is connected, threadId: ${database.threadId}`);
});

// define main route

app.get("/", (req, res) =>
  res.status(200).send("<h1>Welcome to My Connect.in APIs!</h1>")
);

const routers = require("./routers");

app.use("/api", routers.userRouter);
app.use("/api", routers.resetPasswordRouter);

// binding to local port
const PORT = process.env.PORT;

app.listen(PORT, () => console.log(`API IS RUNNING AT PORT: ${PORT}`));
