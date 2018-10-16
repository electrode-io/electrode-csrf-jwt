"use strict";

const Hapi = require("hapi17").hapi;
const Cookie = require("set-cookie-parser");
const pkg = require("../../package.json");
const compat = require("electrode-hapi-compat");
const sinon = require("sinon");

describe("hapi 17 plugin", function() {
  let server;
  const secret = "test";
  const cookieName = "x-csrf-jwt";
  const headerName = "x-csrf-jwt";
  let sandbox;
  let csrfPlugin;
  before(() => {
    sandbox = sinon.sandbox.create();
    sandbox.stub(compat, "isHapi17").returns(true);
    delete require.cache[require.resolve("../..")];
    csrfPlugin = require("../..");
  });
  after(() => {
    sandbox.restore();
    delete require.cache[require.resolve("../..")];
  });

  describe("register", () => {
    it("should fail with bad options", () => {
      server = new Hapi.Server();

      server.register(csrfPlugin).catch(err => {
        expect(err.message).to.contains("hapi-plugin options missing secret");
      });
    });
  });

  describe("cookie config", () => {
    before(() => {
      server = new Hapi.Server();

      const options = {
        secret,
        expiresIn: "2d",
        ignoreThisParam: "ignore",
        cookieConfig: {
          path: undefined,
          isHttpOnly: false
        }
      };

      server.register({ plugin: csrfPlugin, options }).then(() => {
        server.route([
          {
            method: "get",
            path: "/1",
            handler: (request, h) => {
              expect(request.plugins[pkg.name]).to.exist;
              return { message: "hi", jwt: request.plugins[pkg.name].header };
            }
          }
        ]);
      });
    });

    it("should remove path and override isHttpOnly from default", () => {
      return server.inject({ method: "get", url: "/1" }).then(res => {
        const token = res.headers[headerName];
        expect(token).to.be.ok;
        expect(res.statusCode, "GET should return 200").to.equal(200);
        expect(res.payload).to.contain("hi");
        expect(res.headers["set-cookie"][0]).to.contain(`${cookieName}=`);
        const pcookies = Cookie.parse(res.headers["set-cookie"][0], { decodeValues: false });
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
      server = new Hapi.Server();

      const options = {
        secret,
        expiresIn: "2d",
        ignoreThisParam: "ignore",
        shouldSkip: () => flagShouldSkip,
        skipVerify: () => flagSkipVerify,
        skipCreate: () => flagSkipCreate
      };

      server.register({ plugin: csrfPlugin, options }).then(() => {
        server.route([
          {
            method: "get",
            path: "/1",
            handler: request => {
              return { message: "hi" };
            }
          },
          {
            method: "post",
            path: "/2",
            handler: request => {
              return "valid";
            }
          }
        ]);
      });
    });

    beforeEach(() => {
      flagShouldSkip = false;
      flagSkipCreate = false;
      flagSkipVerify = false;
    });

    it("should skip all if shouldSkip returns true", () => {
      flagShouldSkip = true;

      return server.inject({ method: "get", url: "/1" }).then(res => {
        expect(res.request.plugins[pkg.name]).to.not.exist;
        expect(res.statusCode, "GET should return 200").to.equal(200);
        expect(res.payload).to.contain("hi");
        expect(res.headers[headerName]).to.not.exist;
        expect(res.headers["set-cookie"]).to.not.exist;
      });
    });

    it("should skip create if skipCreate returns true", () => {
      flagSkipCreate = true;

      return server.inject({ method: "get", url: "/1" }).then(res => {
        expect(res.request.plugins[pkg.name]).to.not.exist;
        expect(res.statusCode, "GET should return 200").to.equal(200);
        expect(res.payload).to.contain("hi");
        expect(res.headers[headerName]).to.not.exist;
        expect(res.headers["set-cookie"]).to.not.exist;
      });
    });

    it("should skip verify if skipVerify returns true", () => {
      flagSkipVerify = true;

      return server.inject({ method: "get", url: "/1" }).then(res => {
        expect(res.statusCode, "GET should return 200").to.equal(200);
        const token = res.headers[headerName];
        expect(token).to.be.ok;

        return server
          .inject({
            method: "post",
            url: "/2",
            payload: { message: "hello" },
            headers: { [headerName]: token, cookie: `${cookieName}=${token}` }
          })
          .then(res2 => {
            expect(
              res2.statusCode,
              "POST should return 200 even for bad JWT Token due to skipVerify"
            ).to.equal(200);
          });
      });
    });
  });

  describe("csrf", () => {
    before(() => {
      server = new Hapi.Server();

      const options = {
        secret,
        expiresIn: "2d",
        ignoreThisParam: "ignore"
      };

      server.register({ plugin: csrfPlugin, options }).then(() => {
        server.register(require("hapi17").vision).then(() => {
          server.route([
            {
              method: "get",
              path: "/1",
              handler: request => {
                expect(request.plugins[pkg.name]).to.exist;
                return { message: "hi", jwt: request.plugins[pkg.name].header };
              }
            },
            {
              method: "post",
              path: "/2",
              handler: request => {
                expect(request.payload.message).to.equal("hello");
                return "valid";
              }
            },
            {
              method: "get",
              path: "/3",
              handler: request => {
                const tokens = csrfPlugin.hapiCreateToken(request);
                return tokens;
              }
            },
            {
              method: "get",
              path: "/error",
              handler: request => {
                expect(request.plugins[pkg.name]).to.exist;
                throw new Error("fail");
              }
            },
            {
              method: "get",
              path: "/js/bundle",
              handler: request => {
                expect(request.plugins[pkg.name]).to.not.exist;
                return "";
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
        const token = res.headers[headerName];
        expect(token).to.be.ok;
        expect(res.statusCode, "GET should return 200").to.equal(200);
        expect(res.payload).to.contain("hi");
        expect(res.headers["set-cookie"][0]).to.contain(`${cookieName}=`);
        const pcookies = Cookie.parse(res.headers["set-cookie"][0], { decodeValues: false });
        expect(pcookies[0].name).to.equal(cookieName);
        expect(pcookies[0].httpOnly).to.equal(true);
        const cookie = `${pcookies[0].name}=${pcookies[0].value}`;
        return server
          .inject({
            method: "post",
            url: "/2",
            payload: { message: "hello" },
            headers: { [headerName]: token, cookie }
          })
          .then(res2 => {
            expect(
              res2.statusCode,
              `POST JWT should be valid but got ${res2.result.message}`
            ).to.equal(200);

            expect(res2.headers[headerName]).to.exist;
            expect(res2.headers["set-cookie"][0]).to.contain(`${cookieName}=`);
            expect(res2.result).to.equal("valid");
          });
      });
    });

    it("should allow route handler to manually create the tokens", () => {
      return server.inject({ method: "get", url: "/3" }).then(res => {
        const result = res.result;
        expect(result.header).to.exist;
        expect(result.cookie).to.exist;
      });
    });

    it("should skip csrf for /js/ route", () => {
      return server.inject({ method: "get", url: "/js/bundle" }).then(res => {
        expect(res.headers[headerName]).to.not.exist;
        expect(res.request.app.jwt).to.not.exist;
      });
    });

    it("should return 400 for missing jwt", () => {
      return server
        .inject({ method: "post", url: "/2", payload: { message: "hello" } })
        .then(err => {
          expect(err.statusCode).to.equal(400);
          expect(err.result.message).to.equal("MISSING_TOKEN");
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
            payload: { message: "hello" },
            headers: { [headerName]: token, Cookie: `${cookieName}=${token}` }
          })
          .then(res2 => {
            expect(res2.statusCode).to.equal(400);
            expect(res2.result.message).to.equal("INVALID_TOKEN");
            const token = res2.headers[headerName];
            expect(token).to.be.ok;
            expect(res2.headers["set-cookie"][0]).to.contain(`${cookieName}=`);
            const pcookies = Cookie.parse(res2.headers["set-cookie"][0], { decodeValues: false });
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
