"use strict";

const Promise = require("bluebird");
const uuid = require("node-uuid");

const csrf = Promise.promisifyAll(require("./csrf"));
const pkg = require("../package.json");

const MISSING_SECRET = "MISSING_SECRET";
const INVALID_JWT = "INVALID_JWT";

function csrfPlugin(server, options, next) {
  if (!options.secret) {
    return next(new Error(MISSING_SECRET));
  }

  server.ext("onPreResponse", (request, reply) => {
    const id = uuid.v1();
    const headerPayload = {type: "header", uuid: id};
    const cookiePayload = {type: "cookie", uuid: id};

    return Promise.all([
      csrf.createAsync(headerPayload, options),
      csrf.createAsync(cookiePayload, options)
    ]).spread((headerToken, cookieToken) => {
      request.response.headers["X-Csrf-Token"] = headerToken;
      reply.state("jwt", cookieToken);
      return reply.continue();
    }).catch((err) => {
      return reply(err);
    });
  });

  server.ext("onPostAuth", (request, reply) => {
    if (request.method !== "post") {
      return reply.continue();
    }

    const headerPayload = {token: request.headers["X-Csrf-Token"], secret: options.secret};
    const cookiePayload = {token: request.state.jwt, secret: options.secret};

    return Promise.all([
      csrf.verifyAsync(headerPayload),
      csrf.verifyAsync(cookiePayload)
    ]).spread((headerToken, cookieToken) => {
      if (headerToken.uuid === cookieToken.uuid && headerToken.type === "header" && cookieToken.type === "cookie") {
        return reply.continue();
      }
      return reply(new Error(INVALID_JWT));
    }).catch((err) => {
      return reply(err);
    });
  });

  next();
}

csrfPlugin.attributes = {pkg};

module.exports = csrfPlugin;
