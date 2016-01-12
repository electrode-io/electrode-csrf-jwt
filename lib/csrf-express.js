"use strict";

const assert = require("assert");
const Boom = require("boom");
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

  function middleware(req, res, next) {
    if (req.method === "POST") {
      if (!req.body.jwt) {
        return next(new Error("missing jwt"));
      }
      jwt.verify(req.body.jwt, secret, (err, decoded) => {
        if (err || decoded.ip !== req.ip) {
          return next(err || new Error("invalid jwt"));
        }
        return next();
      });
    }

    const payload = {ip: req.ip};
    jwt.sign(payload, secret, params, (token) => {
      req.jwt = token;
      return next();
    });
  };

  return middleware;

}

module.exports = csrfMiddleware;
