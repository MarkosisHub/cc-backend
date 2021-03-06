//handling uncaught exceptions, if something is undefined/uncaught then this will handled
process.on("uncaughtException", (err) => {
  console.log(
    `server is shutting down due to uncaught exception: ${err.message} ${err.stack}`
  );
});

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");

//app initialization
const app = express();

//require db
const connect = require("./config/db");
connect();
//body-parser
app.use(express.json());
//cors
app.use(cors());
//cookieParser
app.use(cookieParser());

//destructure env object
let { SERVER_DEV_NAME } = process.env;

app.get("/", (req, res) => {
  res
    .status(200)
    .send(`${SERVER_DEV_NAME} is running the server at port: ${PORT}`);
});

// Routes
app.use("/api/users", require("./routes/User"));
app.use("/api/cart", require("./routes/Cart"));
app.use("/api/products", require("./routes/Products"));
app.use("/api/orders", require("./routes/Orders"));
app.use("/api/viewed", require("./routes/RecentlyViewProduct"));
app.use("/api/ContactUs", require("./routes/ContactUs"));
app.use("/api/subscribe", require("./routes/Subscribe"))

let PORT = process.env.PORT || 8080;
const server = app.listen(PORT, () =>
  console.log(`server is running at port ${PORT}`)
);

//unhandled promise rejection handling
process.on("unhandledRejection", (err) => {
  console.log(
    "shutting down server due to unhandled promise rejection. Error: " +
      err.message
  );
  server.close(() => {
    process.exit(1);
  });
});
