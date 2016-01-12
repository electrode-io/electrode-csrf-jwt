"use strict";

const assert = require("assert");
const jwt = require("jsonwebtoken");

const payloadOptions = [
  "expiresIn",
  "notBefore",
  "expiresInMinutes",
  "expiresInSeconds",
  "audience",
  "issuer",
  "jwtid",
  "subject",
  "noTimeStamp",
  "headers"
];

function csrfMiddleware(options) {
  assert(options.secret, "secret should exist");

  const params = {};
  payloadOptions.forEach((key) => {
    if (options[key]) {
      params[key] = options[key];
    }
  });

  const secret = options.secret;

  return (req, res, next) => {
    const payload = {ip: req.ip};
    jwt.sign(payload, secret, params, (token) => {
      req.jwt = token;
      return next();
    });
  };

}

module.exports = csrfMiddleware;
