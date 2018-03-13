"use strict";

const CSRF = require("./csrf");
const pkg = require("../package.json");
const makeCookieConfig = require("./make-cookie-config");

function csrfMiddleware(options) {
  if (!options || !options.secret) {
    throw new Error(`${pkg.name}: koa-middleware options missing secret`);
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

  return function middleware(ctx, next) {
    csrf.process(
      {
        request: ctx,
        method: ctx.method,
        create: () => {
          const tokens = csrf.create();

          ctx.set(csrf.headerName, tokens.header);
          ctx.cookies.set(csrf.cookieName, tokens.cookie, cookieConfig);
        },
        verify: () => csrf.verify(ctx.headers[csrf.headerName], ctx.cookies.get(csrf.cookieName)),
        continue: () => next(),
        error: verify => ctx.throw(verify.error)
      },
      {}
    );
  };
}

module.exports = csrfMiddleware;
