"use strict";

const Fastify = require("fastify");
const electrodeCsrf = require("../../lib");
const csrfPlugin = require("../../lib").fastify;
const Cookie = require("set-cookie-parser");
const pkg = require("../../package.json");
csrfPlugin[Symbol.for("skip-override")] = true;
const fastifyCookie = require("fastify-cookie");

describe("fastify plugin", function() {
  let server;
  const secret = "test";
  const cookieName = "x-csrf-jwt";
  const headerName = "x-csrf-jwt";

  describe("register", () => {
    after(() => {
      server.close();
    });

    it("should fail with bad options", done => {
      server = Fastify();
      server.register(csrfPlugin);
      server.listen(3000, err => {
        if (err) {
          expect(err.message).to.contains("fastify-plugin options missing secret");
          done();
        }
      });
    });
  });

  describe("cookie config", () => {
    before(() => {
      server = Fastify();

      const options = {
        secret,
        expiresIn: "2d",
        ignoreThisParam: "ignore",
        cookieConfig: {
          path: undefined,
          httpOnly: false
        }
      };

      server.register(fastifyCookie).register(csrfPlugin, options);
      server.route({
        method: "GET",
        path: "/",
        handler: function(request, reply) {
          reply.send({ hello: "world" });
        }
      });
    });

    it("should remove path and override httpOnly from default", () => {
      return server.inject({ method: "get", url: "/" }).then(res => {
        const token = res.headers[headerName];
        expect(token).to.be.ok;
        expect(res.statusCode, "GET should return 200").to.equal(200);
        expect(res.payload).to.contain("hello");
        expect(res.headers["set-cookie"]).to.contain(`${cookieName}=`);
        const pcookies = Cookie.parse(res.headers["set-cookie"], { decodeValues: false });
        expect(pcookies[0].name).to.equal(cookieName);
        expect(pcookies[0].httpOnly).to.equal(undefined);
        expect(pcookies[0].path).to.equal(undefined);
      });
    });
  });

  describe("skip callbacks", () => {
    let flagShouldSkip;
    let flagSkipVerify;
    let flagSkipCreate;

    before(() => {
      server = Fastify();

      const options = {
        secret,
        expiresIn: "2d",
        ignoreThisParam: "ignore",
        shouldSkip: () => flagShouldSkip,
        skipVerify: () => flagSkipVerify,
        skipCreate: () => flagSkipCreate
      };

      server.register(fastifyCookie).register(csrfPlugin, options);
      server.route({
        method: "GET",
        path: "/",
        handler: function(request, reply) {
          reply.send({ hello: "world" });
        }
      });
      server.route({
        method: "GET",
        path: "/1",
        config: {
          shouldSkip: true
        },
        handler: function(request, reply) {
          reply.send({ hello: "world" });
        }
      });
      server.route({
        method: "POST",
        path: "/test",
        handler: function(request, reply) {
          reply.send(request.body);
        }
      });
    });

    beforeEach(() => {
      flagShouldSkip = false;
      flagSkipCreate = false;
      flagSkipVerify = false;
    });

    it("should skip all if shouldSkip returns true", () => {
      flagShouldSkip = true;

      return server.inject({ method: "get", url: "/" }).then(res => {
        expect(res.statusCode, "GET should return 200").to.equal(200);
        expect(res.payload).to.contain("hello");
        expect(res.headers[headerName]).to.not.exist;
        expect(res.headers["set-cookie"]).to.not.exist;
      });
    });

    it("should skip create if skipCreate returns true", () => {
      flagSkipCreate = true;

      return server.inject({ method: "get", url: "/" }).then(res => {
        expect(res.statusCode, "GET should return 200").to.equal(200);
        expect(res.payload).to.contain("hello");
        expect(res.headers[headerName]).to.not.exist;
        expect(res.headers["set-cookie"]).to.not.exist;
      });
    });

    it("should skip verify if skipVerify returns true", () => {
      flagSkipVerify = true;

      return server.inject({ method: "get", url: "/" }).then(res => {
        expect(res.statusCode, "GET should return 200").to.equal(200);
        const token = res.headers[headerName];
        console.log(token);
        expect(token).to.be.ok;

        return server
          .inject({
            method: "post",
            url: "/test",
            payload: { message: "hello" },
            headers: { [headerName]: token },
            cookies: { [cookieName]: token }
          })
          .then(res2 => {
            expect(
              res2.statusCode,
              "POST should return 200 even for bad JWT Token due to skipVerify"
            ).to.equal(200);
          });
      });
    });

    it("should skip all if shouldSkip returns true at route level", () => {
      return server.inject({ method: "get", url: "/1" }).then(res => {
        expect(res.statusCode, "GET should return 200").to.equal(200);
        expect(res.payload).to.contain("hello");
        expect(res.headers[headerName]).to.not.exist;
        expect(res.headers["set-cookie"]).to.not.exist;
      });
    });
  });

  describe("csrf", () => {
    before(() => {
      server = Fastify();

      const options = {
        secret,
        expiresIn: "2d",
        ignoreThisParam: "ignore"
      };

      server.register(fastifyCookie).register(csrfPlugin, options);
      server.route({
        method: "GET",
        path: "/1",
        handler: function(request, reply) {
          reply.send({ hello: "world" });
        }
      });

      server.route({
        method: "POST",
        path: "/2",
        handler: function(request, reply) {
          expect(request.body.hello).to.equal("world");
          reply.send("valid");
        }
      });
    });

    it("should return success for GET and then POST", () => {
      return server.inject({ method: "get", url: "/1" }).then(res => {
        const token = res.headers[headerName];
        expect(token).to.be.ok;
        expect(res.statusCode, "GET should return 200").to.equal(200);
        expect(res.payload).to.contain("world");
        expect(res.headers["set-cookie"]).to.contain(`${cookieName}=`);
        const pcookies = Cookie.parse(res.headers["set-cookie"], { decodeValues: false });
        expect(pcookies[0].name).to.equal(cookieName);
        expect(pcookies[0].httpOnly).to.equal(true);
        return server
          .inject({
            method: "post",
            url: "/2",
            payload: { hello: "world" },
            headers: { [headerName]: token },
            cookies: { [pcookies[0].name]: pcookies[0].value }
          })
          .then(res2 => {
            expect(res2.statusCode, `POST JWT should be valid but got ${res2.body}`).to.equal(200);

            expect(res2.headers[headerName]).to.exist;
            expect(res2.headers["set-cookie"]).to.contain(`${cookieName}=`);
            expect(res2.body).to.equal("valid");
          });
      });
    });

    it("should return 400 for missing jwt", () => {
      return server.inject({ method: "post", url: "/2", payload: { hello: "world" } }).then(err => {
        expect(err.statusCode).to.equal(400);
        expect(err.json().message).to.equal("MISSING_TOKEN");
      });
    });

    it("should return 400 for invalid jwt", () => {
      return server.inject({ method: "get", url: "/1" }).then(res => {
        const token = res.headers[headerName];
        expect(token, "Must have JWT header token").to.exist;
        return server
          .inject({
            method: "post",
            url: "/2",
            payload: { hello: "world" },
            headers: { [headerName]: token },
            cookies: { [cookieName]: token }
          })
          .then(res2 => {
            expect(res2.statusCode).to.equal(400);
            expect(res2.json().message).to.equal("INVALID_TOKEN");
            const token = res2.headers[headerName];
            expect(token).to.be.ok;
            expect(res2.headers["set-cookie"]).to.contain(`${cookieName}=`);
            const pcookies = Cookie.parse(res2.headers["set-cookie"], { decodeValues: false });
            expect(pcookies[0].name).to.equal(cookieName);
            expect(pcookies[0].httpOnly).to.equal(true);
          });
      });
    });

    it("should completely skip for http OPTIONS", () => {
      return server.inject({ method: "options", url: "/1" }).then(res => {
        const token = res.headers[headerName];
        expect(token, "should not have header token").to.be.undefined;
        expect(res.headers["set-cookie"], "should not have set-cookie header").to.be.undefined;
      });
    });

    it("should completely skip for http TRACE", () => {
      return server.inject({ method: "trace", url: "/1" }).then(res => {
        const token = res.headers[headerName];
        expect(token, "should not have header token").to.be.undefined;
        expect(res.headers["set-cookie"], "should not have set-cookie header").to.be.undefined;
      });
    });
  });
});
