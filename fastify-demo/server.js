"use strict";

const Fastify = require("fastify");
const csrfPlugin = require("../lib").fastify;
const fastifyCookie = require("fastify-cookie");
const fastifyStatic = require("fastify-static");
const fastifyCors = require("fastify-cors");
const crypto = require("crypto");
const path = require("path");
const SECRET_SIZE = 1024;
csrfPlugin[Symbol.for("skip-override")] = true;

const start = () => {
  const server = Fastify();
  const options = {
    secret: crypto.randomBytes(SECRET_SIZE),
    expiresIn: 60,
    shouldSkip: request => {
      // return true to skip CSRF JWT for given request
      return false;
    },
    skipCreate: request => {
      // return true to skip creating CSRF JWT Token for given request
      return false;
    },
    skipVerify: request => {
      // return true to skip verifying CSRF JWT Token for given request
      return false;
    }
  };
  server
    .register(fastifyCors, {
      origin: true
    })
    .register(fastifyStatic, {
      root: path.join(__dirname, "/public")
    })
    .register(fastifyCookie)
    .register(csrfPlugin, options);
  server.route({
    method: "GET",
    path: "/",
    config: {
      shouldSkip: true
    },
    handler: function(request, reply) {
      reply.sendFile("index.html");
    }
  });
  server.route({
    method: "GET",
    path: "/getTokens",
    handler: function(request, reply) {
      reply.send({ hello: "world" });
    }
  });
  server.route({
    method: "POST",
    path: "/testPost",
    handler: function(request, reply) {
      reply.send(request.body);
    }
  });
  return server;
};

const fastify = start();
fastify.listen(3000, err => {
  if (err) throw err;
  console.log(`Server listening at http://localhost:${fastify.server.address().port}`);
});
