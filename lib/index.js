"use strict";

const csrfHapi = require("./csrf-hapi");
const csrfExpress = require("./csrf-express");

module.exports = {
  hapiPlugin: csrfHapi,
  expressMiddleware: csrfExpress
};
