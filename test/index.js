"use strict";

const Hapi = require("hapi");
const csrfPlugin = require("../").hapiPlugin;

const chai = require("chai");
const expect = chai.expect;
const jwt = require("jsonwebtoken");

let server;
const secret = "test";

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

        server.views({
          engines: {
            html: require("handlebars")
          },
          relativeTo: __dirname,
          path: "templates"
        });

        server.route([
          {
            method: "get",
            path: "/1",
            handler: (request, reply) => {
              expect(request.plugins.jwt).to.exist;

              return reply.view("index", {message: "hi", jwt: request.plugins.jwt});
            }
          },
          {
            method: "post",
            path: "/2",
            handler: (request, reply) => {
              expect(request.payload.message).to.equal("hello");
              expect(request.payload.jwt).to.equal(request.plugins.jwt);
              return reply("valid");
            }
          }
        ]);
      });
    });
  });

  it("return success", (done) => {
    return server.inject({method: "get", url: "/1"})
      .then((res) => {
        const token = res.request.plugins.jwt;
        expect(res.statusCode).to.equal(200);
        expect(res.payload).to.contain(token);
        expect(res.payload).to.contain("hi");
        return server.inject({method: "post", url: "/2", payload: {message: "hello", jwt: token}})
          .then((res) => {
            expect(res.statusCode).to.equal(200);
            expect(res.result).to.equal("valid");
            done();
          });
      })
      .catch((err) => {
        expect(err).to.not.exist;
        done();
      });
  });

  it("return 500 for missing jwt", (done) => {
    server.inject({method: "post", url: "/2", payload: {message: "hello"}})
      .then((err) => {
        expect(err.statusCode).to.equal(500);
        done();
      });
  });

  it("return 500 for wrong ip", (done) => {
    const token = jwt.sign({ip: "123.123.123.123"}, secret, {});

    server.inject({method: "post", url: "/2", payload: {message: "hello", jwt: token}})
      .then((err) => {
        expect(err.statusCode).to.equal(500);
        done();
      });
  });

  it("return 500 for invalid jwt", (done) => {
    server.inject({method: "post", url: "/2", payload: {message: "hello", jwt: "123"}})
      .then((err) => {
        expect(err.statusCode).to.equal(500);
        done();
      });
  });
});
