"use strict";

const Fs = require("fs");
const Path = require("path");
const staticPaths = require("electrode-static-paths");
const electrodeServer = require("electrode-server");
const crypto = require("crypto");
const electrodeCsrf = require("..");
const pkg = require("../package.json");

const SECRET_SIZE = 1024;

electrodeServer(
  {
    //
    // Because any respectable browser would block cross site request by
    // doing a preflight (OPTIONS) check first and fail without CORS,
    // below explicitly enabled CORS to demo that badsite.com is not
    // allowed to make POST due to script setting HTTP header.
    //
    // Note that electrode-server automatically enables CORS in
    // development mode.
    //
    // WARNING: For demo only, do not do this in production app
    //
    connections: {
      default: {
        routes: {
          cors: true
        }
      }
    },
    plugins: {
      electrodeStaticPaths: {
        options: {
          pathPrefix: "demo"
        }
      },
      csrf: {
        module: Path.join(__dirname, "../lib/csrf-hapi"),
        options: {
          cookieConfig: {
            // remove http only for debugging
            // WARNING: For demo only, do not do this in production app
            isHttpOnly: false
          },
          secret: crypto.randomBytes(SECRET_SIZE)
        }
      }
    }
  },
  [staticPaths()]
).then(server => {
  const indexFile = Fs.readFileSync(Path.join(__dirname, "html/index.html")).toString();
  const marker = "<!--{{CSRF_HEADER_TOKEN}}-->";

  server.route([
    {
      path: "/",
      method: "get",
      handler: (request, reply) => {
        const tokens = electrodeCsrf.hapiCreateToken(request);
        reply(
          indexFile.replace(
            marker,
            `<script>
window.localStorage &&
window.localStorage.setItem("initial-csrf-header-token",
"${tokens.header}");
</script>`
          )
        );
      }
    },
    //
    // Hapi automatically check Access-Control-Request-Headers and refuse OPTIONS
    // request from badsite.com even if CORS is allowed.  So explicitly create an
    // OPTIONS route to return Access-Control-Allow-Origin, and show that the browser
    // triggers the header not allowed error.
    //
    // Note: Cross site headers can be controlled by Access-Control-Allow-Headers
    //
    // WARNING: For demo only, do not do this in production app
    //
    {
      path: "/api/1",
      method: "options",
      handler: (request, reply) => {
        reply();
      }
    },
    {
      path: "/api/1",
      method: "post",
      handler: (request, reply) => {
        reply({ hello: "world" });
      },
      config: {
        plugins: {
          [pkg.name]: {
            allowFirstPost: true
          }
        }
      }
    },
    {
      path: "/api/2",
      method: "get",
      handler: (request, reply) => {
        reply({ api: 2 });
      }
    }
  ]);
});
