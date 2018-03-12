"use strict";

const jwt = require("jsonwebtoken");
const UUID = require("uuid");

const MISSING_JWT = "MISSING_JWT";
const INVALID_JWT = "INVALID_JWT";
const BAD_JWT = "BAD_JWT";

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

class JwtTokenEngine {
  constructor(options) {
    options = Object.assign({ secret: "csrf jwt secret" }, options);
    this._secret = options.secret;
  }

  create(payload, options) {
    const uuid = UUID.v4();
    const params = {};

    if (options) {
      payloadOptions.forEach(key => {
        if (options[key]) {
          params[key] = options[key];
        }
      });
    }

    return {
      header: jwt.sign(Object.assign({}, payload, { uuid, type: "header" }), this._secret, params),
      cookie: jwt.sign(Object.assign({}, payload, { uuid, type: "cookie" }), this._secret, params)
    };
  }

  verify(header, cookie) {
    let error;

    if (!header || !cookie) {
      error = new Error(MISSING_JWT);
    } else {
      try {
        header = jwt.verify(header, this._secret);
        cookie = jwt.verify(cookie, this._secret);
        const valid =
          header.uuid &&
          header.uuid === cookie.uuid &&
          header.type === "header" &&
          cookie.type === "cookie";

        if (!valid) {
          error = new Error(INVALID_JWT);
        }
      } catch (e) {
        error = new Error(BAD_JWT);
      }
    }

    return {
      error,
      header,
      cookie
    };
  }
}

module.exports = JwtTokenEngine;
