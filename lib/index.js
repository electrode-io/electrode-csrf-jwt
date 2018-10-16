"use strict";

const csrfHapi = require("./csrf-hapi");
const csrfHapi17 = require("./csrf-hapi17");
const csrfExpress = require("./csrf-express");
const csrfKoa = require("./csrf-koa");
const pkg = require("../package.json");
const { isHapi17 } = require("electrode-hapi-compat");

module.exports = {
  register: isHapi17() ? csrfHapi17.register : csrfHapi,
  pkg: isHapi17() ? csrfHapi17.pkg : undefined,
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
