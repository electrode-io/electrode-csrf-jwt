"use strict";

const bodyParser = require("body-parser");
const cookieParser = require('cookie-parser');
const express = require("express");
const csrfMiddleware = require("../../lib/index").expressMiddleware;
const jwt = require("jsonwebtoken");

const fetch = require("isomorphic-fetch");

const secret = "test";
const url = "http://localhost:3000";
let server;

describe("test register", () => {
  it("should fail with bad options", () => {
    const app = express();
    try {
      app.use(csrfMiddleware());
    } catch (e) {
      expect(e.message).to.equal("MISSING_SECRET");
    }
  });
});

describe("test csrf-jwt express middleware", () => {
  before(() => {
    const app = express();

    app.use(bodyParser.urlencoded({extended: false}));
    app.use(bodyParser.json());
    app.use(cookieParser());

    const options = {
      secret,
      expiresIn: "2d",
      ignoreThisParam: "ignore"
    };
    app.use(csrfMiddleware(options));

    app.get("/1", (req, res) => {
      res.end("valid");
    });

    app.post("/2", (req, res) => {
      expect(req.body.message).to.equal("hello");
      return res.end("valid");
    });

    server = require("http").createServer(app);
    server.listen(3000);
  });

  after(() => {
    server.close();
  });

  it("should return success", () => {
    return fetch(`${url}/1`)
      .then((res) => {
        expect(res.status).to.equal(200);
        const csrfHeader = res.headers.get("x-csrf-jwt");
        const csrfCookie = res.headers.get("set-cookie");
        expect(csrfHeader).to.exist;
        expect(csrfCookie).to.contain("x-csrf-jwt=");

        return fetch(`${url}/2`, {
          method: "POST",
          headers: {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "x-csrf-jwt": csrfHeader,
            "Cookie": csrfCookie
          },
          body: JSON.stringify({message: "hello"})
        }).then((res) => {
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
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({message: "hello"})
    }).then((res) => {
      expect(res.status).to.equal(500);
      expect(res.headers.get("x-csrf-jwt")).to.not.exist;
      expect(res.headers.get("set-cookie")).to.not.exist;
    });
  });

  it("should return 500 for invalid jwt", () => {
    return fetch(`${url}/1`)
      .then(() => {
        const token = jwt.sign({uuid: "1"}, secret, {});
        return fetch(`${url}/2`, {
          method: "POST",
          headers: {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "x-csrf-jwt": token,
            "Cookie": `x-csrf-jwt=${token}`
          },
          body: JSON.stringify({message: "hello"})
        }).then((res) => {
          expect(res.status).to.equal(500);
          return fetch(`${url}/2`, {
            method: "POST",
            headers: {
              "Accept": "application/json",
              "Content-Type": "application/json",
              "x-csrf-jwt": "invalid",
              "Cookie": `x-csrf-jwt=${token}`
            },
            body: JSON.stringify({message: "hello"})
          }).then((res) => {
            expect(res.status).to.equal(500);
          });
        });
      });
  });
});
