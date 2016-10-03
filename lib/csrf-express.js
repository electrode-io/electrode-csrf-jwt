"use strict";

const Promise = require("bluebird");
const uuid = require("uuid");
const csrf = require("./csrf");

const MISSING_SECRET = "MISSING_SECRET";
const INVALID_JWT = "INVALID_JWT";

function csrfMiddleware(options) {
  if (!options || !options.secret) {
    throw new Error(MISSING_SECRET);
  }

  function middleware(req, res, next) {

    function createToken() {
      const id = uuid.v4();
      const headerPayload = {type: "header", uuid: id};
      const cookiePayload = {type: "cookie", uuid: id};

      return Promise.all([
        csrf.create(headerPayload, options),
        csrf.create(cookiePayload, options)
      ]).spread((headerToken, cookieToken) => {
        res.header("x-csrf-jwt", headerToken);
        res.cookie("x-csrf-jwt", cookieToken);
        return next();
      });
    }

    function verifyAndCreateToken() {
      const headerPayload = {token: req.headers["x-csrf-jwt"], secret: options.secret};
      const cookiePayload = {token: req.cookies["x-csrf-jwt"], secret: options.secret};

      return Promise.all([
        csrf.verify(headerPayload),
        csrf.verify(cookiePayload)
      ]).spread((headerToken, cookieToken) => {
        if (headerToken.uuid === cookieToken.uuid &&
          headerToken.type === "header" && cookieToken.type === "cookie") {
          return createToken();
        }
        return next(new Error(INVALID_JWT));
      }).catch((err) => {
        return next(err);
      });
    }

    const method = req.method.toUpperCase();
    if (method !== "GET" && method !== "HEAD") {
      return verifyAndCreateToken();
    }

    return createToken();
  }

  return middleware;
}

module.exports = csrfMiddleware;
