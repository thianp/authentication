const express = require("express");
const app = express();
const cors = require("cors");
const morgan = require("morgan");

require('dotenv').config()
require('./config/passport')

const userRoute = require("./routes/userRoute");
const todoRoute = require("./routes/todoRoute");
const notFoundMiddleWare = require("./middlewares/notFound");
const errorMiddleWare = require("./middlewares/error");
const UserMiddleware = require("./middlewares/userAuthorize");
const { sequelize } = require("./models");
const passportJwt = require('./middlewares/passportJwt')

// ## MIDDLEWARE
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ## ROUTES
app.use("/api/users", userRoute);
app.use("/api/todo", passportJwt,todoRoute);

// ## NOTFOUND & ERROR
app.use(notFoundMiddleWare);
app.use(errorMiddleWare);
const port = 8002;
// sequelize.sync({ force: true }).then(() => console.log("DATABASE SYNC"))
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
