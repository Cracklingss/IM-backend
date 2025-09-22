const cookieParser = require("cookie-parser");
const cors = require("cors");
const express = require("express");
const app = express();
const PORT = 5000;
const routes = require("./routes");

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: "http://localhost:3000",
    credentials: true
  })
)

app.use("/api/auth", routes);

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
})