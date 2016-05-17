"use strict";

const bodyParser = require("body-parser");
const cookieParser = require('cookie-parser');
const express = require("express");
const exphbs = require("express-handlebars");
const csrfMiddleware = require("../").expressMiddleware;
const jwt = require("jsonwebtoken");

const chai = require("chai");
const expect = chai.expect;
const request = require("superagent");

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

describe.skip("test csrf-jwt express middleware", () => {
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
      res.json({message: "hi"});
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
    return request.get(`${url}/1`)
      .end((err, res) => {
        expect(err).to.not.exist;
        expect(res.statusCode).to.equal(200);
        expect(res.body.message).to.equal("hi");
        expect(res.headers["x-csrf-jwt"]).to.exist;
        expect(res.headers["set-cookie"][0]).to.contain("x-csrf-jwt=");

        return request.post(`${url}/2`)
          .send({message: "hello"})
          .set("x-csrf-jwt", res.headers["x-csrf-jwt"])
          .set("Cookie", res.headers["set-cookie"][0])
          .end((err, res) => {
            expect(res.statusCode).to.equal(200);
            expect(res.headers["x-csrf-jwt"]).to.exist;
            expect(res.headers["set-cookie"][0]).to.contain("x-csrf-jwt=");
            expect(res.text).to.equal("valid");
          });
      });
  });

  it("should return 500 for missing jwt", () => {
    return request.post(`${url}/2`)
      .send({message: "hello"})
      .end((err) => {
        expect(err.status).to.equal(500);
      });
  });

  it("should return 500 for invalid jwt", () => {
    return request.get(`${url}/1`)
      .end((err, res) => {
        const token = jwt.sign({uuid: "1"}, secret, {});
        return request.post(`${url}/2`)
          .send({message: "hello"})
          .set("x-csrf-jwt", token)
          .set("Cookie", `x-csrf-jwt=${token}`)
          .end((err, res) => {
            expect(res.statusCode).to.equal(500);
            return request.post(`${url}/2`)
              .send({message: "hello"})
              .set("x-csrf-jwt", "invalid")
              .end((err, res) => {
                expect(res.statusCode).to.equal(500);
              });
          });
      });
  });
});
