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

  function middleware(ctx, next) {

    function createToken() {
      const id = uuid.v4();
      const headerPayload = {type: "header", uuid: id};
      const cookiePayload = {type: "cookie", uuid: id};

      return Promise.all([
        csrf.create(headerPayload, options),
        csrf.create(cookiePayload, options)
      ]).spread((headerToken, cookieToken) => {
        ctx.set("x-csrf-jwt", headerToken);
        ctx.cookies.set("x-csrf-jwt", cookieToken);
        return next();
      });
    }

    function verifyAndCreateToken() {
      const headerPayload = {token: ctx.headers["x-csrf-jwt"], secret: options.secret};
      const cookiePayload = {token: ctx.cookies.get("x-csrf-jwt"), secret: options.secret};

      return Promise.all([
        csrf.verify(headerPayload),
        csrf.verify(cookiePayload)
      ]).spread((headerToken, cookieToken) => {
        if (headerToken.uuid === cookieToken.uuid &&
          headerToken.type === "header" && cookieToken.type === "cookie") {
          return createToken();
        }
        ctx.throw(new Error(INVALID_JWT));
      }).catch((err) => {
        ctx.throw(err);
      });
    }

    const method = ctx.method.toUpperCase();
    if (method !== "GET" && method !== "HEAD") {
      return verifyAndCreateToken();
    }

    return createToken();
  }

  return middleware;
}

module.exports = csrfMiddleware;
