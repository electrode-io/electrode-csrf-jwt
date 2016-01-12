"use strict";

const Hapi = require("hapi");

const chai = require("chai");
const expect = chai.expect;

const jwt = require("jsonwebtoken");

describe("test csrf-jwt", () => {
  it("return view with jwt", (done) => {
    const server = new Hapi.Server();
    server.connection();

    const options = {
      secret: "test",
      expiresIn: "2d",
      ignoreThisParam: "ignore"
    };

    server.register({register: require("../"), options}, (err) => {
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
              expect(request.payload).to.deep.equal({message: "hello", jwt: request.plugins.jwt});

              return reply("valid");
            }
          }
        ]);

        server.inject({method: "get", url: "/1"}, (res) => {
          const token = res.request.plugins.jwt;
          expect(res.payload).to.contain(token);
          expect(res.payload).to.contain("hi");

          server.inject({method: "post", url: "/2", payload: {message: "hello", jwt: token}}, (res) => {
            expect(res.statusCode).to.equal(200);
            expect(res.result).to.equal("valid");

            server.inject({method: "post", url: "/2", payload: {message: "hello"}}, (res) => {
              expect(res.statusCode).to.equal(403);

              const token = jwt.sign({ip: "123.123.123.123"}, options.secret, {});

              server.inject({method: "post", url: "/2", payload: {message: "hello", jwt: token}}, (res) => {
                expect(res.statusCode).to.equal(403);

                server.inject({method: "post", url: "/2", payload: {message: "hello", jwt: "123"}}, (res) => {
                  expect(res.statusCode).to.equal(403);
                });
              });
            });

          });

          done();
        });
      });
    });
  });
});
