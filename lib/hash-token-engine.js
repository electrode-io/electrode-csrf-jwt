"use strict";

/* eslint-disable no-magic-numbers */

/*
 * This is a Token Engine (experimental) that instead of using JWT, it uses SHA (256)
 * and a large (1024+ bytes) secret to verify the tokens.  The tokens are not encrypted.
 * The idea is that it's not that important if they are not because anyone can openly
 * get valid tokens by making a GET request anyways.  What's important is the browser
 * restriction on XSS access to read/write cookies and setting HTTP headers.
 *
 * The implementation:
 *
 *   - contentA = payload + timeStamp + uuid1
 *   - shaContent = contentA + secret
 *   - shaKey = uuid2
 *   - shaSum = sha256(shaContent + shaKey)
 *   => headerToken = contentA + shaSum
 *   => cookieToken = shaKey
 *
 * This also allows the cookieToken to be just a relatively smaller UUID compare to
 * a long JWT token.
 *
 * Of course this means the tokens cannot contain any sensitive info.
 */

const crypto = require("crypto");
const assert = require("assert");
const getIdGenerator = require("./get-id-generators");
const pkg = require("../package.json");
const ms = require("ms");
const { MISSING_TOKEN, INVALID_TOKEN, BAD_TOKEN } = require("./errors");

const encodePayload = payload => {
  return Buffer.from(JSON.stringify(payload)).toString("base64");
};

const decodePayload = epayload => {
  return epayload ? JSON.parse(Buffer.from(epayload, "base64").toString()) : {};
};

const version = "1";

class HashTokenEngine {
  constructor(options) {
    const secret = `${pkg.name} ShaTokenEngine: you should set a 1024+ bytes secret`;

    this._uuidGen = getIdGenerator(options.uuidGen);

    assert(this._uuidGen(), "UUID generator must not return falsy values");

    this._secret = options.secret || secret;

    if (this._secret.length < 1024) {
      console.error(secret); // eslint-disable-line
    }

    this._expiresIn = options.expiresIn || "1h";
    this._hashAlgo = options.hashAlgo || "sha256";
  }

  _calcContentSum(content) {
    const hash = crypto.createHash(this._hashAlgo);
    hash.update(content);
    return hash.digest("base64");
  }

  _encode(content, shaKey) {
    const contentFull = `${content}-${this._secret}-${shaKey}`;
    const shaSum = this._calcContentSum(contentFull);

    return { header: `${content}.${shaSum}`, cookie: shaKey };
  }

  create(payload) {
    payload = payload ? encodePayload(payload) : "";
    const nowSec = Math.floor(Date.now() / 1000).toString(36);
    const uuid = this._uuidGen();
    const contentPart1 = `${version}.${nowSec}.${this._expiresIn}.${payload}.${uuid}`;

    return this._encode(contentPart1, this._uuidGen());
  }

  _verifyTokens(parts, shaKey) {
    const getExpireTime = (timeSec, expiresIn) => {
      const expiresMs = ms(expiresIn);
      return parseInt(timeSec, 36) * 1000 + expiresMs;
    };

    if (
      parts[0] !== version ||
      parts.length < 6 ||
      getExpireTime(parts[1], parts[2]) < Date.now()
    ) {
      return false;
    }

    const content = `${version}.${parts[1]}.${parts[2]}.${parts[3]}.${parts[4]}-${
      this._secret
    }-${shaKey}`;

    const shaSum = this._calcContentSum(content);

    if (shaSum !== parts[5]) {
      return false;
    }

    return true;
  }

  verify(header, cookie) {
    let error;

    if (!header || !cookie) {
      error = new Error(MISSING_TOKEN);
    } else {
      try {
        const parts = header.split(".");
        if (!this._verifyTokens(parts, cookie)) {
          error = new Error(INVALID_TOKEN);
        } else {
          const payload = decodePayload(parts[3]);
          header = Object.assign({ type: "header", uuid: parts[4] }, payload);
          cookie = Object.assign({ type: "cookie", uuid: parts[4] }, payload);
        }
      } catch (e) {
        error = new Error(BAD_TOKEN);
      }
    }

    return {
      error,
      header,
      cookie
    };
  }
}

module.exports = HashTokenEngine;
