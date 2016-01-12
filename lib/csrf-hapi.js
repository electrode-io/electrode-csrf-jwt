"use strict";

const csrf = require("./csrf");
const pkg = require("../package.json");

const MISSING_SECRET = "MISSING_SECRET";

function csrfPlugin(server, options, next) {
  if (!options.secret) {
    return next(new Error(MISSING_SECRET));
  }

  server.ext("onRequest", (request, reply) => {
    const payload = {ip: request.info.remoteAddress};

    csrf.create(payload, options, (err, token) => {
      if (err) {
        return reply(err);
      }

      request.plugins.jwt = token;
      return reply.continue();
    });
  });

  server.ext("onPostAuth", (request, reply) => {
    if (request.method !== "post") {
      return reply.continue();
    }

    const req = {
      token: request.payload.jwt,
      secret: options.secret,
      ip: request.info.remoteAddress
    };
    csrf.verify(req, (err) => {
      if (err) {
        return reply(err);
      }
      return reply.continue();
    });

  });

  next();
}

csrfPlugin.attributes = {pkg};

module.exports = csrfPlugin;
