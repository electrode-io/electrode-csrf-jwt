"use strict";

const Hapi = require("hapi");
const csrfPlugin = require("../../lib/index").register;

const jwt = require("jsonwebtoken");

let server;
const secret = "test";

describe("test register", () => {
  it("should fail with bad options", () => {
    server = new Hapi.Server();
    server.connection();

    server.register({register: csrfPlugin}, (err) => {
      expect(err.message).to.equal("MISSING_SECRET");
    });
  });
});

describe("test csrf-jwt hapi plugin", () => {
  before(() => {
    server = new Hapi.Server();
    server.connection();

    const options = {
      secret,
      expiresIn: "2d",
      ignoreThisParam: "ignore"
    };

    server.register({register: csrfPlugin, options}, (err) => {
      expect(err).to.not.exist;

      server.register(require("vision"), (err) => {
        expect(err).to.not.exist;

        server.route([
          {
            method: "get",
            path: "/1",
            handler: (request, reply) => {
              expect(request.app.jwt).to.exist;
              return reply({message: "hi", jwt: request.app.jwt});
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
            path: "/js/bundle",
            handler: (request, reply) => {
              expect(request.app.jwt).to.not.exist;
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

  it("should return success", () => {
    return server.inject({method: "get", url: "/1"}, (res) => {
      const token = res.request.app.jwt;
      expect(res.statusCode).to.equal(200);
      expect(res.payload).to.contain("hi");
      expect(res.headers["x-csrf-jwt"]).to.equal(token);
      expect(res.headers["set-cookie"][0]).to.contain("jwt=");
      return server.inject({
        method: "post",
        url: "/2",
        payload: {message: "hello"},
        headers: {"x-csrf-jwt": token, Cookie: res.headers["set-cookie"][0]}
      }, (res) => {
        expect(res.statusCode).to.equal(200);
        expect(res.headers["x-csrf-jwt"]).to.exist;
        expect(res.headers["set-cookie"][0]).to.contain("x-csrf-jwt=");
        expect(res.result).to.equal("valid");
      });
    });
  });

  it("should skip csrf for /js/ route", () => {
    return server.inject({method: "get", url: "/js/bundle"}, (res) => {
      expect(res.headers["x-csrf-jwt"]).to.not.exist;
      expect(res.request.app.jwt).to.not.exist;
    });
  });

  it("should return 400 for missing jwt", () => {
    return server.inject({method: "post", url: "/2", payload: {message: "hello"}}, (err) => {
      expect(err.statusCode).to.equal(400);
      expect(err.result.message).to.equal("INVALID_JWT");
    });
  });

  it("should return 400 for invalid jwt", () => {
    return server.inject({method: "get", url: "/1"}, (res) => {
      const token = res.request.app.jwt;
      return server.inject({
        method: "post",
        url: "/2",
        payload: {message: "hello"},
        headers: {"x-csrf-jwt": token, Cookie: `x-csrf-jwt=${token}`}
      }, (res) => {
        expect(res.statusCode).to.equal(400);
        expect(res.result.message).to.equal("INVALID_JWT");
      });
    });
  });
});
