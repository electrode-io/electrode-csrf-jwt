"use strict";

const Promise = require("bluebird");
const uuid = require("uuid");

const csrf = Promise.promisifyAll(require("./csrf"));
const pkg = require("../package.json");

const MISSING_SECRET = "MISSING_SECRET";
const INVALID_JWT = "INVALID_JWT";

function csrfPlugin(server, options, next) {
  if (!options.secret) {
    return next(new Error(MISSING_SECRET));
  }

  server.ext("onPostAuth", (request, reply) => {

    function createToken() {
      const id = uuid.v1();
      const headerPayload = {type: "header", uuid: id};
      const cookiePayload = {type: "cookie", uuid: id};

      return Promise.all([
        csrf.createAsync(headerPayload, options),
        csrf.createAsync(cookiePayload, options)
      ]).spread((headerToken, cookieToken) => {
        request.app.jwt = headerToken;
        reply.state("x-csrf-jwt", cookieToken, {
          path: "/"
        });
        return reply.continue();
      });
    }

    function verifyAndCreateToken() {

      const headerPayload = {token: request.headers["x-csrf-jwt"], secret: options.secret};
      const cookiePayload = {token: request.state["x-csrf-jwt"], secret: options.secret};

      return Promise.all([
        csrf.verifyAsync(headerPayload),
        csrf.verifyAsync(cookiePayload)
      ]).spread((headerToken, cookieToken) => {
        if (headerToken.uuid === cookieToken.uuid &&
          headerToken.type === "header" && cookieToken.type === "cookie") {
          return createToken();
        }
        return reply(new Error(INVALID_JWT));
      }).catch((err) => {
        return reply(err);
      });
    }

    if (request.method === "post") {
      return verifyAndCreateToken();
    }

    // hack to exclude js and css bundle requests
    if (request.path.indexOf("/js/") !== 0)
      return createToken();

    return reply.continue();
  });

  server.ext("onPreResponse", (request, reply) => {
    const headers = request.response && request.response.headers;
    if (headers) {
      headers["x-csrf-jwt"] = request.app.jwt;
    }
    return reply.continue();
  });

  return next();
}

csrfPlugin.attributes = {pkg};

module.exports = csrfPlugin;
