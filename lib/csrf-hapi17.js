"use strict";

/* eslint-disable consistent-return */

const Boom = require("boom");
const CSRF = require("./csrf");
const pkg = require("../package.json");
const makeCookieConfig = require("./make-cookie-config");
const constants = require("./constants");

function csrfPlugin(server, options) {
  if (!options.secret) {
    return new Error(`${pkg.name}: hapi-plugin options missing secret`);
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

  const createToken = (request, payload) => {
    const plugin = request.plugins[pkg.name];

    if (plugin) {
      if (!plugin.tokens) {
        plugin.tokens = csrf.create(payload);
        plugin.createToken = undefined;
      }

      return plugin.tokens;
    }

    return undefined;
  };

  server.ext("onPreAuth", (request, h) => {
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
        continue: () => h.continue,
        error: verify => {
          throw new Boom(verify.error.message);
        }
      },
      routeConfig
    );

    return h.continue;
  });

  server.ext("onPreResponse", (request, h) => {
    const tokens = createToken(request);

    if (tokens) {
      const headers = request.response.isBoom
        ? request.response.output.headers
        : request.response.headers;

      h.state(csrf.cookieName, tokens.cookie, cookieConfig);

      headers[csrf.headerName] = tokens.header;
    }

    return h.continue;
  });
}

module.exports = {
  register: csrfPlugin,
  pkg
};
