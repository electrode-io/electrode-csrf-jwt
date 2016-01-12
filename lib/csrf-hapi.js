"use strict";

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

const MISSING_SECRET = "MISSING_SECRET";
const MISSING_JWT = "MISSING_JWT";
const INVALID_JWT = "INVALID_JWT";

function csrfPlugin(server, options, next) {
  if(!options.secret){
    return next(new Error(MISSING_SECRET));
  }

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
      return reply(new Error(MISSING_JWT));
    }

    jwt.verify(request.payload.jwt, secret, (err, decoded) => {
      if (err || decoded.ip !== request.info.remoteAddress) {
        return reply(err || new Error(INVALID_JWT));
      }
      return reply.continue();
    });

  });

  next();
}

csrfPlugin.attributes = {pkg};

module.exports = csrfPlugin;
