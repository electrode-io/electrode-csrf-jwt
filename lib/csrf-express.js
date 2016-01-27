"use strict";

const Promise = require("bluebird");
const uuid = require("node-uuid");
const csrf = Promise.promisifyAll(require("./csrf"));

const MISSING_SECRET = "MISSING_SECRET";
const INVALID_JWT = "INVALID_JWT";

function csrfMiddleware(options) {
  if (!options || !options.secret) {
    throw new Error(MISSING_SECRET);
  }

  function middleware(req, res, next) {

    function createToken() {
      const id = uuid.v1();
      const headerPayload = {type: "header", uuid: id};
      const cookiePayload = {type: "cookie", uuid: id};

      return Promise.all([
        csrf.createAsync(headerPayload, options),
        csrf.createAsync(cookiePayload, options)
      ]).spread((headerToken, cookieToken) => {
        res.header("x-csrf-token", headerToken);
        res.cookie("jwt", cookieToken);
        return next();
      });
    }

    function verifyAndCreateToken() {
      const headerPayload = {token: req.headers["x-csrf-token"], secret: options.secret};
      const cookiePayload = {token: req.cookies.jwt, secret: options.secret};

      return Promise.all([
        csrf.verifyAsync(headerPayload),
        csrf.verifyAsync(cookiePayload)
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

    if (req.method === "POST") {
      return verifyAndCreateToken();
    }

    return createToken();
  }

  return middleware;
}

module.exports = csrfMiddleware;
