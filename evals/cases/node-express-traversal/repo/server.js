const express = require("express");
const path = require("path");

const app = express();
const PUBLIC = path.join(__dirname, "public");

app.get("/file", (req, res) => {
  const name = req.query.name;
  res.sendFile(path.join(PUBLIC, name));
});

app.get("/hello", (req, res) => {
  res.send(`<h1>Hello ${req.query.who}</h1>`);
});

app.get("/hello-safe", (req, res) => {
  res.type("text/plain").send(`Hello ${String(req.query.who)}`);
});

module.exports = app;
