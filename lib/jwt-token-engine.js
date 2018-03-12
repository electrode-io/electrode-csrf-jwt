"use strict";

const jwt = require("jsonwebtoken");
const assert = require("assert");
const getIdGenerator = require("./get-id-generators");
const { MISSING_TOKEN, INVALID_TOKEN, BAD_TOKEN } = require("./errors");

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

    this._uuidGen = getIdGenerator(options.uuidGen);

    assert(this._uuidGen(), "UUID generator must not return falsy values");

    this._secret = options.secret;

    this._params = {};

    payloadOptions.forEach(key => {
      if (options[key]) {
        this._params[key] = options[key];
      }
    });
  }

  create(payload) {
    const uuid = this._uuidGen();

    return {
      header: jwt.sign(
        Object.assign({}, payload, { uuid, type: "header" }),
        this._secret,
        this._params
      ),
      cookie: jwt.sign(
        Object.assign({}, payload, { uuid, type: "cookie" }),
        this._secret,
        this._params
      )
    };
  }

  verify(header, cookie) {
    let error;

    if (!header || !cookie) {
      error = new Error(MISSING_TOKEN);
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
          error = new Error(INVALID_TOKEN);
        }
      } catch (e) {
        error = new Error(e.message === "jwt expired" ? INVALID_TOKEN : BAD_TOKEN);
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
