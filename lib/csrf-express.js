"use strict";

const JwtTokenEngine = require("./jwt-token-engine");
const pkg = require("../package.json");
const makeCookieConfig = require("./make-cookie-config");

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

  const falseCb = () => false;
  const skipCreate = options.skipCreate || falseCb;
  const skipVerify = options.skipVerify || falseCb;
  const shouldSkip = options.shouldSkip || falseCb;

  const engine = new JwtTokenEngine({ secret: options.secret });

  function middleware(req, res, next) {
    // completely skip CSRF JWT
    if (shouldSkip(req)) {
      return next();
    }

    function createToken() {
      if (skipCreate(req)) return;

      const tokens = engine.create({}, options);
      res.header("x-csrf-jwt", tokens.header);
      res.cookie("x-csrf-jwt", tokens.cookie, cookieConfig);
    }

    // Skip verify for HTTP GET or HEAD or if user indicate skip verify
    const method = req.method.toUpperCase();
    if (method === "GET" || method === "HEAD" || skipVerify(req)) {
      createToken();
      return next();
    }

    // verify and create new CSRF tokens
    createToken();

    const verify = engine.verify(req.headers["x-csrf-jwt"], req.cookies["x-csrf-jwt"]);

    return next(verify.error);
  }

  return middleware;
}

module.exports = csrfMiddleware;
