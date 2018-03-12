"use strict";

const bodyParser = require("koa-bodyparser");
const Router = require("koa-router");
const Koa = require("koa");
const csrfMiddleware = require("../../lib/index").koaMiddleware;
const jwt = require("jsonwebtoken");

const fetch = require("isomorphic-fetch");

describe("koa middleware", function() {
  const secret = "test";
  const url = "http://localhost:4000";

  describe("register", () => {
    it("should fail with bad options", () => {
      const app = new Koa();
      try {
        app.use(csrfMiddleware());
      } catch (e) {
        expect(e.message).to.contain("koa-middleware options missing secret");
      }
    });
  });

  const createMockServer = options => {
    const app = new Koa();
    app.silent = true;
    const router = new Router();

    app.use(bodyParser());

    options = Object.assign(
      {
        secret,
        expiresIn: "2d",
        ignoreThisParam: "ignore"
      },
      options
    );
    app.use(csrfMiddleware(options));

    router.get("/1", ctx => {
      ctx.body = "valid";
    });

    router.post("/2", ctx => {
      expect(ctx.request.body.message).to.equal("hello");
      ctx.body = "valid";
    });

    app.use(router.routes());

    const server = require("http").createServer(app.callback());
    server.listen(4000);

    return server;
  };

  describe("csrf", () => {
    let server;
    before(() => {
      server = createMockServer();
    });

    after(() => {
      server.close();
    });

    it("should return success", () => {
      return fetch(`${url}/1`).then(res => {
        expect(res.status).to.equal(200);
        const csrfHeader = res.headers.get("x-csrf-jwt");
        const csrfCookie = res.headers.get("set-cookie");
        expect(csrfHeader).to.exist;
        expect(csrfCookie).to.contain("x-csrf-jwt=");
        expect(csrfCookie).to.contain("httponly");

        return fetch(`${url}/2`, {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "x-csrf-jwt": csrfHeader,
            Cookie: csrfCookie
          },
          body: JSON.stringify({ message: "hello" })
        }).then(res => {
          expect(res.status).to.equal(200);
          expect(res.headers.get("x-csrf-jwt")).to.exist;
          expect(res.headers.get("set-cookie")).to.contain("x-csrf-jwt=");
        });
      });
    });

    it("should return 500 for missing jwt", () => {
      return fetch(`${url}/2`, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ message: "hello" })
      }).then(res => {
        expect(res.status).to.equal(500);
        expect(res.headers.get("x-csrf-jwt")).to.not.exist;
        expect(res.headers.get("set-cookie")).to.not.exist;
      });
    });

    it("should return 500 for invalid jwt", () => {
      return fetch(`${url}/1`).then(() => {
        const token = jwt.sign({ uuid: "1" }, secret, {});
        return fetch(`${url}/2`, {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "x-csrf-jwt": token,
            Cookie: `x-csrf-jwt=${token}`
          },
          body: JSON.stringify({ message: "hello" })
        }).then(res => {
          expect(res.status).to.equal(500);
          return fetch(`${url}/2`, {
            method: "POST",
            headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
              "x-csrf-jwt": "invalid",
              Cookie: `x-csrf-jwt=${token}`
            },
            body: JSON.stringify({ message: "hello" })
          }).then(res => {
            expect(res.status).to.equal(500);
          });
        });
      });
    });
  });

  describe("skip callbacks", function() {
    let flagShouldSkip;
    let flagSkipVerify;
    let flagSkipCreate;
    let server;

    before(() => {
      server = createMockServer({
        shouldSkip: () => flagShouldSkip,
        skipVerify: () => flagSkipVerify,
        skipCreate: () => flagSkipCreate
      });
    });

    beforeEach(() => {
      flagShouldSkip = false;
      flagSkipCreate = false;
      flagSkipVerify = false;
    });

    after(() => {
      server.close();
    });

    it("should skip all if shouldSkip returns true", () => {
      flagShouldSkip = true;

      return fetch(`${url}/1`).then(res => {
        expect(res.status).to.equal(200);
        const csrfHeader = res.headers.get("x-csrf-jwt");
        const csrfCookie = res.headers.get("set-cookie");
        expect(csrfHeader).to.not.exist;
        expect(csrfCookie).to.not.exist;
      });
    });

    it("should skip create if skipCreate returns true", () => {
      flagSkipCreate = true;

      return fetch(`${url}/1`).then(res => {
        expect(res.status).to.equal(200);
        const csrfHeader = res.headers.get("x-csrf-jwt");
        const csrfCookie = res.headers.get("set-cookie");
        expect(csrfHeader).to.not.exist;
        expect(csrfCookie).to.not.exist;
      });
    });

    it("should skip verify if skipVerify returns true", () => {
      flagSkipVerify = true;

      return fetch(`${url}/1`).then(res => {
        expect(res.status).to.equal(200);
        const csrfHeader = res.headers.get("x-csrf-jwt");
        const csrfCookie = res.headers.get("set-cookie");
        expect(csrfHeader).to.exist;
        expect(csrfCookie).to.contain("x-csrf-jwt=");
        expect(csrfCookie).to.contain("httponly");

        return fetch(`${url}/2`, {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "x-csrf-jwt": csrfHeader,
            Cookie: `x-csrf-jwt=${csrfHeader}`
          },
          body: JSON.stringify({ message: "hello" })
        }).then(res => {
          expect(res.status).to.equal(200);
          expect(res.headers.get("x-csrf-jwt")).to.exist;
          expect(res.headers.get("set-cookie")).to.contain("x-csrf-jwt=");
        });
      });
    });
  });
});
