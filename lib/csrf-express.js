"use strict";

const csrf = require("./csrf");

const MISSING_SECRET = "MISSING_SECRET";

function csrfMiddleware(options) {
  if (!options.secret) {
    throw new Error(MISSING_SECRET);
  }

  function middleware(req, res, next) {
    if (req.method === "POST") {
      const request = {
        token: req.body.jwt,
        secret: options.secret,
        ip: req.ip
      };
      return csrf.verify(request, (err) => {
        if (err) {
          return next(err);
        }
        return next();
      });
    }

    const payload = {ip: req.ip};
    return csrf.create(payload, options, (err, token) => {
      if (err) {
        return next(err);
      }
      req.jwt = token;
      return next();
    });
  }

  return middleware;
}

module.exports = csrfMiddleware;
