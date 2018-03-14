"use strict";

const csrfHapi = require("./csrf-hapi");
const csrfExpress = require("./csrf-express");
const csrfKoa = require("./csrf-koa");
const pkg = require("../package.json");

module.exports = {
  register: csrfHapi,
  expressMiddleware: csrfExpress,
  koaMiddleware: csrfKoa,
  hapiCreateToken: (request, payload) => {
    const plugin = request.plugins[pkg.name];

    if (plugin) {
      if (plugin.createToken) {
        return plugin.createToken(request, payload);
      }

      return plugin.tokens || {};
    }

    return {};
  }
};
