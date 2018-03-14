"use strict";

const onHeaders = require("on-headers");
const CSRF = require("./csrf");
const pkg = require("../package.json");
const makeCookieConfig = require("./make-cookie-config");
const constants = require("./constants");

function csrfMiddleware(options) {
  if (!options || !options.secret) {
    throw new Error(`${pkg.name}: express-middleware options missing secret`);
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

  return function middleware(req, res, next) {
    csrf.process(
      {
        request: req,
        method: req.method,
        firstPost: req.headers[constants.firstPostHeaderName],
        create: () => {
          // use on-headers to defer creating and setting tokens
          onHeaders(res, () => {
            const tokens = csrf.create();
            res.header(csrf.headerName, tokens.header);
            res.cookie(csrf.cookieName, tokens.cookie, cookieConfig);
          });
        },
        verify: () => csrf.verify(req.headers[csrf.headerName], req.cookies[csrf.cookieName]),
        continue: () => next(),
        error: verify => next(verify.error)
      },
      {}
    );
  };
}

module.exports = csrfMiddleware;
