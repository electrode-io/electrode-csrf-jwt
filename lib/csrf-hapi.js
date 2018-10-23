"use strict";

const Boom = require("boom");
const CSRF = require("./csrf");
const pkg = require("../package.json");
const makeCookieConfig = require("./make-cookie-config");
const constants = require("./constants");

function csrfPlugin(server, options, next) {
  if (!options.secret) {
    return next(new Error(`${pkg.name}: hapi-plugin options missing secret`));
  }

  const cookieConfig = makeCookieConfig(
    {
      path: "/",
      isSecure: false,
      // prevent scripts from reading the cookie
      isHttpOnly: true
    },
    options.cookieConfig
  );

  const csrf = new CSRF(options);

  const createToken = (request, paylaod) => {
    const plugin = request.plugins[pkg.name];

    if (plugin) {
      if (!plugin.tokens) {
        plugin.tokens = csrf.create(paylaod);
        request.app.jwt = plugin.tokens.header;
        plugin.createToken = undefined;
      }

      return plugin.tokens;
    }

    return undefined;
  };

  server.ext("onPreAuth", (request, reply) => {
    const routeConfig = request.route.settings.plugins[pkg.name] || {};

    csrf.process(
      {
        request,
        method: request.method,
        firstPost: request.headers[constants.firstPostHeaderName],
        create: () => {
          // initialize plugin in request to let onPreResponse to create tokens later
          request.plugins[pkg.name] = { createToken };
        },
        verify: () => csrf.verify(request.headers[csrf.headerName], request.state[csrf.cookieName]),
        continue: () => reply.continue(),
        error: verify => reply(Boom.badRequest(verify.error.message))
      },
      routeConfig
    );
  });

  server.ext("onPreResponse", (request, reply) => {
    const tokens = createToken(request);

    if (tokens) {
      const headers = request.response.isBoom
        ? request.response.output.headers
        : request.response.headers;

      reply.state(csrf.cookieName, tokens.cookie, cookieConfig);

      headers[csrf.headerName] = tokens.header;
    }

    reply.continue();
  });

  return next();
}

csrfPlugin.attributes = { pkg };

module.exports = csrfPlugin;
