"use strict";

const jwt = require("jsonwebtoken");

const MISSING_JWT = "MISSING_JWT";
const INVALID_JWT = "INVALID_JWT";

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

function create(payload, options, callback) {
  const params = {};
  payloadOptions.forEach((key) => {
    if (options[key]) {
      params[key] = options[key];
    }
  });

  const secret = options.secret;
  jwt.sign(payload, secret, params, (token) => {
    return callback(null, token);
  });
}

function verify(request, callback) {
  const token = request.token;
  const secret = request.secret;
  const ip = request.ip;

  if (!token) {
    return callback(new Error(MISSING_JWT));
  }

  jwt.verify(token, secret, (err, decoded) => {
    if (err || decoded.ip !== ip) {
      return callback(err || new Error(INVALID_JWT));
    }
    return callback();
  });
}

module.exports = {
  create,
  verify
};
