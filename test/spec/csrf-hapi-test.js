"use strict";

const Hapi = require("hapi");
const csrfPlugin = require("../../lib/index").register;
const Cookie = require("set-cookie-parser");

const jwt = require("jsonwebtoken");

let server;
const secret = "test";

describe("hapi plugin register", () => {
  it("should fail with bad options", () => {
    server = new Hapi.Server();
    server.connection();

    server.register({ register: csrfPlugin }, err => {
      expect(err.message).to.equal("MISSING_SECRET");
    });
  });
});

describe("hapi plugin", () => {
  before(() => {
    server = new Hapi.Server();
    server.connection();

    const options = {
      secret,
      expiresIn: "2d",
      ignoreThisParam: "ignore"
    };

    server.register({ register: csrfPlugin, options }, err => {
      expect(err).to.not.exist;

      server.register(require("vision"), err => {
        expect(err).to.not.exist;

        server.route([
          {
            method: "get",
            path: "/1",
            handler: (request, reply) => {
              expect(request.plugins["csrf-jwt"]).to.exist;
              return reply({ message: "hi", jwt: request.plugins["csrf-jwt"].headerToken });
            }
          },
          {
            method: "post",
            path: "/2",
            handler: (request, reply) => {
              expect(request.payload.message).to.equal("hello");
              return reply("valid");
            }
          },
          {
            method: "get",
            path: "/error",
            handler: (request, reply) => {
              expect(request.plugins["csrf-jwt"]).to.exist;
              return reply(new Error("fail"));
            }
          },
          {
            method: "get",
            path: "/js/bundle",
            handler: (request, reply) => {
              expect(request.plugins["csrf-jwt"]).to.not.exist;
              return reply("");
            },
            config: {
              plugins: {
                "electrode-csrf-jwt": {
                  enabled: false
                }
              }
            }
          }
        ]);
      });
    });
  });

  it("should return success for GET and then POST", () => {
    return server.inject({ method: "get", url: "/1" }).then(res => {
      const token = res.request.plugins["csrf-jwt"].headerToken;
      expect(token).to.be.ok;
      expect(res.statusCode, "GET should return 200").to.equal(200);
      expect(res.payload).to.contain("hi");
      expect(res.headers["x-csrf-jwt"]).to.equal(token);
      expect(res.headers["set-cookie"][0]).to.contain("jwt=");
      const pcookies = Cookie.parse(res.headers["set-cookie"][0], { decodeValues: false });
      expect(pcookies[0].name).to.equal("x-csrf-jwt");
      expect(pcookies[0].httpOnly).to.equal(true);
      const cookie = `${pcookies[0].name}=${pcookies[0].value}`;
      return server
        .inject({
          method: "post",
          url: "/2",
          payload: { message: "hello" },
          headers: { "x-csrf-jwt": token, cookie }
        })
        .then(res2 => {
          expect(
            res2.statusCode,
            `POST JWT should be valid but got ${res2.result.message}`
          ).to.equal(200);

          expect(res2.headers["x-csrf-jwt"]).to.exist;
          expect(res2.headers["set-cookie"][0]).to.contain("x-csrf-jwt=");
          expect(res2.result).to.equal("valid");
        });
    });
  });

  it("should skip csrf for /js/ route", () => {
    return server.inject({ method: "get", url: "/js/bundle" }).then(res => {
      expect(res.headers["x-csrf-jwt"]).to.not.exist;
      expect(res.request.app.jwt).to.not.exist;
    });
  });

  it("should return 400 for missing jwt", () => {
    return server.inject({ method: "post", url: "/2", payload: { message: "hello" } }).then(err => {
      expect(err.statusCode).to.equal(400);
      expect(err.result.message).to.equal("INVALID_JWT");
    });
  });

  it("should return 400 for invalid jwt", () => {
    return server.inject({ method: "get", url: "/1" }).then(res => {
      const token = res.request.plugins["csrf-jwt"].headerToken;
      expect(token, "Must have JWT header token").to.exist;
      return server
        .inject({
          method: "post",
          url: "/2",
          payload: { message: "hello" },
          headers: { "x-csrf-jwt": token, Cookie: `x-csrf-jwt=${token}` }
        })
        .then(res => {
          expect(res.statusCode).to.equal(400);
          expect(res.result.message).to.equal("INVALID_JWT");
        });
    });
  });

  it("should not set cookie or header for error response", () => {
    return server.inject({ method: "get", url: "/error" }).then(res => {
      expect(res.headers).to.not.have.property("set-cookie");
      expect(res.headers).to.not.have.property("x-csrf-jwt");
    });
  });
});
