"use strict";

const CSRF = require("./csrf");
const pkg = require("../package.json");
const makeCookieConfig = require("./make-cookie-config");
const constants = require("./constants");
const httpErrors = require("http-errors");

const csrfPlugin = (server, options, next) => {
  if (!options.secret) {
    return next(new Error(`${pkg.name}: fastify-plugin options missing secret`));
  }

  const cookieConfig = makeCookieConfig(
    {
      path: "/",
      secure: false,
      // prevent scripts from reading the cookie
      httpOnly: true
    },
    options.cookieConfig
  );

  const csrf = new CSRF(options);

  server.addHook("preValidation", (request, reply, done) => {
    const routeConfig = reply.context.config;
    csrf.process(
      {
        request,
        method: request.raw.method,
        firstPost: request.headers[constants.firstPostHeaderName],
        create: () => {
          const tokens = csrf.create(request.body);
          reply.setCookie(csrf.cookieName, tokens.cookie, cookieConfig);
          reply.header(csrf.headerName, tokens.header);
        },
        verify: () =>
          csrf.verify(request.headers[csrf.headerName], request.cookies[csrf.cookieName]),
        continue: () => done(),
        error: verify => {
          /* eslint-disable new-cap */
          reply.send(httpErrors.BadRequest(verify.error.message));
          done();
        }
      },
      routeConfig
    );
  });

  return next();
};

module.exports = csrfPlugin;
