"use strict";

const csrfHapi = require("./csrf-hapi");
const csrfExpress = require("./csrf-express");
const csrfKoa = require("./csrf-koa");

module.exports = {
  register: csrfHapi,
  expressMiddleware: csrfExpress,
  koaMiddleware: csrfKoa
};
