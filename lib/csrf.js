"use strict";

const jwt = require("jsonwebtoken");
const Promise = require("bluebird");
const createToken = Promise.promisify(jwt.sign);
const verifyToken = Promise.promisify(jwt.verify);

const MISSING_JWT = "MISSING_JWT";

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

function create(payload, options) {
  const params = {};
  payloadOptions.forEach((key) => {
    if (options[key]) {
      params[key] = options[key];
    }
  });

  const secret = options.secret;
  return createToken(payload, secret, params);
}

function verify(payload) {
  const token = payload.token;
  const secret = payload.secret;

  if (!token) {
    return Promise.reject(new Error(MISSING_JWT));
  }

  return verifyToken(token, secret);
}

module.exports = {
  create,
  verify
};
