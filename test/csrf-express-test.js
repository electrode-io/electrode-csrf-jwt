"use strict";

const bodyParser = require("body-parser");
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
  it("should fail with bad options", (done) => {
    const app = express();
    try {
      app.use(csrfMiddleware());
    } catch (e) {
      expect(e.message).to.equal("MISSING_SECRET");
      done();
    }
  });
});

describe("test csrf-jwt express middleware", () => {
  before(() => {
    const app = express();

    app.use(bodyParser.urlencoded({extended: false}));
    app.use(bodyParser.json());

    app.engine(".html", exphbs({extname: ".html"}));
    app.set("view engine", "html");
    app.set("views", __dirname + "/templates");

    const options = {
      secret,
      expiresIn: "2d",
      ignoreThisParam: "ignore"
    };
    app.use(csrfMiddleware(options));

    app.get("/1", (req, res) => {
      expect(req.jwt).to.exist;
      res.json({message: "hi", jwt: req.jwt});
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

  it("should return success", (done) => {
    return request.get(`${url}/1`)
      .end((err, res) => {
        expect(err).to.not.exist;
        expect(res.statusCode).to.equal(200);
        expect(res.body.message).to.equal("hi");
        expect(res.body.jwt).to.exist;

        return request.post(`${url}/2`)
          .send({message: "hello", jwt: res.body.jwt})
          .end((err, res) => {
            expect(res.statusCode).to.equal(200);
            expect(res.text).to.equal("valid");
            done();
          });
      });
  });

  it("should return 500 for missing jwt", (done) => {
    return request.post(`${url}/2`)
      .send({message: "hello"})
      .end((err) => {
        expect(err.status).to.equal(500);
        done();
      });
  });

  it("should return 500 for wrong ip", (done) => {
    const token = jwt.sign({ip: "123.123.123.123"}, secret, {});

    return request.post(`${url}/2`)
      .send({message: "hello", jwt: token})
      .end((err) => {
        expect(err.status).to.equal(500);
        done();
      });
  });

  it("should return 500 for invalid jwt", (done) => {
    const token = jwt.sign({ip: "127.0.0.1"}, "ssh");

    return request.post(`${url}/2`)
      .send({message: "hello", jwt: token})
      .end((err) => {
        expect(err.status).to.equal(500);
        done();
      });
  });
});
