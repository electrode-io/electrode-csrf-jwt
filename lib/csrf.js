"use strict";

/* eslint-disable complexity */

const JwtTokenEngine = require("./jwt-token-engine");
const HashTokenEngine = require("./hash-token-engine");
const constants = require("./constants");
const errors = require("./errors");

class CSRF {
  constructor(options) {
    const falseCb = () => false;
    this._skipCreate = options.skipCreate || falseCb;
    this._skipVerify = options.skipVerify || falseCb;
    this._shouldSkip = options.shouldSkip || falseCb;
    this.cookieName = options.cookieName || constants.cookieName;
    this.headerName = options.headerName || this.cookieName;
    this.engine =
      options.tokenEngine === "hash" ? new HashTokenEngine(options) : new JwtTokenEngine(options);
  }

  create(payload) {
    return this.engine.create(payload);
  }

  verify(header, cookie) {
    return this.engine.verify(header, cookie);
  }

  process(ctx, routeConfig) {
    const method = ctx.method.toUpperCase();

    // completely skip the CSRF process
    if (
      method === "OPTIONS" ||
      method === "TRACE" ||
      this._shouldSkip(ctx.request) ||
      routeConfig.enabled === false ||
      routeConfig.shouldSkip === true
    ) {
      return ctx.continue();
    }

    const createToken = () => {
      if (this._skipCreate(ctx.request) || routeConfig.skipCreate === true) {
        return;
      }

      ctx.create();
    };

    // Skip verify for HTTP GET/HEAD or if user indicate skip verify
    if (
      method === "GET" ||
      method === "HEAD" ||
      this._skipVerify(ctx.request) ||
      routeConfig.skipVerify === true
    ) {
      createToken();
      return ctx.continue();
    }

    // verify and create new CSRF tokens
    const verify = ctx.verify();
    createToken();

    if (verify.error) {
      return ctx.error(verify);
    }

    if (ctx.firstPost && routeConfig.allowFirstPost !== true) {
      verify.error = new Error(errors.FIRST_POST_NOT_ALLOWED);
      return ctx.error(verify);
    }

    return ctx.continue();
  }
}

module.exports = CSRF;
