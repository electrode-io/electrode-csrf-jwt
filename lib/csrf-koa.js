"use strict";

const pkg = require("../package.json");
const makeCookieConfig = require("./make-cookie-config");
const JwtTokenEngine = require("./jwt-token-engine");

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

  const falseCb = () => false;
  const skipCreate = options.skipCreate || falseCb;
  const skipVerify = options.skipVerify || falseCb;
  const shouldSkip = options.shouldSkip || falseCb;

  const engine = new JwtTokenEngine({ secret: options.secret });

  function middleware(ctx, next) {
    // completely skip CSRF JWT
    if (shouldSkip(ctx)) {
      return next();
    }

    function createToken() {
      if (skipCreate(ctx)) return;

      const tokens = engine.create({}, options);

      ctx.set("x-csrf-jwt", tokens.header);
      ctx.cookies.set("x-csrf-jwt", tokens.cookie, cookieConfig);
    }

    // Skip verify for HTTP GET or HEAD or if user indicate skip verify
    const method = ctx.method.toUpperCase();
    if (method === "GET" || method === "HEAD" || skipVerify(ctx)) {
      createToken();
      return next();
    }

    // verify and create new CSRF tokens
    createToken();

    const verify = engine.verify(ctx.headers["x-csrf-jwt"], ctx.cookies.get("x-csrf-jwt"));

    if (verify.error) {
      return ctx.throw(verify.error);
    }

    return next();
  }

  return middleware;
}

module.exports = csrfMiddleware;
