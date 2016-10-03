"use strict";

const Boom = require("boom");
const Promise = require("bluebird");
const uuid = require("uuid");

const csrf = require("./csrf");
const pkg = require("../package.json");

const MISSING_SECRET = "MISSING_SECRET";
const INVALID_JWT = "INVALID_JWT";

function csrfPlugin(server, options, next) {
  if (!options.secret) {
    return next(new Error(MISSING_SECRET));
  }

  server.ext("onPreAuth", (request, reply) => {

    function createToken() {
      const id = uuid.v4();
      const headerPayload = {type: "header", uuid: id};
      const cookiePayload = {type: "cookie", uuid: id};

      return Promise.all([
        csrf.create(headerPayload, options),
        csrf.create(cookiePayload, options)
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
        csrf.verify(headerPayload),
        csrf.verify(cookiePayload)
      ]).spread((headerToken, cookieToken) => {
        if (headerToken.uuid === cookieToken.uuid &&
          headerToken.type === "header" && cookieToken.type === "cookie") {
          return createToken();
        }
        return reply(Boom.badRequest(INVALID_JWT));
      }).catch(() => {
        return reply(Boom.badRequest(INVALID_JWT));
      });
    }

    function shouldSkip() {
      return request.route.settings.plugins["electrode-csrf-jwt"] &&
        request.route.settings.plugins["electrode-csrf-jwt"].enabled === false;
    }

    if (shouldSkip()) {
      return reply.continue();
    }

    const method = request.method.toUpperCase();
    if (method !== "GET" && method !== "HEAD") {
      return verifyAndCreateToken();
    }

    return createToken();
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
