"use strict";

const Boom = require("boom");
const JwtTokenEngine = require("./jwt-token-engine");
const pkg = require("../package.json");
const makeCookieConfig = require("./make-cookie-config");

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

  const cookieName = options.cookieName || "x-csrf-jwt";
  const headerName = options.headerName || cookieName;

  const falseCb = () => false;
  const skipCreate = options.skipCreate || falseCb;
  const skipVerify = options.skipVerify || falseCb;
  const shouldSkip = options.shouldSkip || falseCb;

  const engine = new JwtTokenEngine(options);

  server.ext("onPreAuth", (request, reply) => {
    const routeConfig = request.route.settings.plugins[pkg.name] || {};

    // completely skip CSRF JWT
    if (shouldSkip(request) || routeConfig.enabled === false || routeConfig.shouldSkip === true) {
      return reply.continue();
    }

    function createToken() {
      if (skipCreate(request) || routeConfig.skipCreate === true) {
        return;
      }

      // initialize plugin in request to let onPreResponse to create tokens later
      request.plugins[pkg.name] = {};
    }

    // Skip verify for HTTP GET or HEAD or if user indicate skip verify
    const method = request.method.toUpperCase();
    if (
      method === "GET" ||
      method === "HEAD" ||
      skipVerify(request) ||
      routeConfig.skipVerify === true
    ) {
      createToken();
      return reply.continue();
    }

    // verify and create new CSRF tokens
    createToken();

    const verify = engine.verify(request.headers[headerName], request.state[cookieName]);

    if (verify.error) {
      return reply(Boom.badRequest(verify.error.message));
    }

    return reply.continue();
  });

  server.ext("onPreResponse", (request, reply) => {
    const plugin = request.plugins[pkg.name];

    if (plugin) {
      const headers = request.response.isBoom
        ? request.response.output.headers
        : request.response.headers;

      const tokens = engine.create();
      reply.state(cookieName, tokens.cookie, cookieConfig);

      headers[headerName] = tokens.header;
    }

    return reply.continue();
  });

  return next();
}

csrfPlugin.attributes = { pkg };

module.exports = csrfPlugin;
