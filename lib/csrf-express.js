"use strict";

const onHeaders = require("on-headers");
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

  const cookieName = options.cookieName || "x-csrf-jwt";
  const headerName = options.headerName || cookieName;

  const falseCb = () => false;
  const skipCreate = options.skipCreate || falseCb;
  const skipVerify = options.skipVerify || falseCb;
  const shouldSkip = options.shouldSkip || falseCb;

  const engine = new JwtTokenEngine(options);

  function middleware(req, res, next) {
    const method = req.method.toUpperCase();

    // completely skip CSRF JWT
    if (method === "OPTIONS" || method === "TRACE" || shouldSkip(req)) {
      return next();
    }

    function createToken() {
      if (skipCreate(req)) return;

      // use on-headers to defer creating and setting tokens
      onHeaders(res, () => {
        const tokens = engine.create({});
        res.header(headerName, tokens.header);
        res.cookie(cookieName, tokens.cookie, cookieConfig);
      });
    }

    // Skip verify for HTTP GET/HEAD or if user indicate skip verify
    if (method === "GET" || method === "HEAD" || skipVerify(req)) {
      createToken();
      return next();
    }

    // verify and create new CSRF tokens
    createToken();

    const verify = engine.verify(req.headers[headerName], req.cookies[cookieName]);

    return next(verify.error);
  }

  return middleware;
}

module.exports = csrfMiddleware;
