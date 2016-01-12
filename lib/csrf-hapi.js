"use strict";

const Boom = require("boom");
const assert = require("assert");
const jwt = require("jsonwebtoken");
const pkg = require("../package.json");

const internals = {};

internals.payloadOptions = [
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

function csrfPlugin(server, options, next) {
  assert(options.secret, "secret should exist");

  const params = {};
  internals.payloadOptions.forEach((key) => {
    if (options[key]) {
      params[key] = options[key];
    }
  });

  const secret = options.secret;

  server.ext("onRequest", (request, reply) => {
    const payload = {ip: request.info.remoteAddress};

    jwt.sign(payload, secret, params, (token) => {
      request.plugins.jwt = token;
      return reply.continue();
    });
  });

  server.ext("onPostAuth", (request, reply) => {
    if (request.method !== "post") {
      return reply.continue();
    }

    if (!request.payload.jwt) {
      return reply(Boom.forbidden());
    }

    jwt.verify(request.payload.jwt, secret, (err, decoded) => {
      if (err || decoded.ip !== request.info.remoteAddress) {
        return reply(Boom.forbidden());
      }
      return reply.continue();
    });

  });

  next();
}

csrfPlugin.attributes = {pkg};

module.exports = csrfPlugin;
