# Electrode CSRF JWT

[![NPM version][npm-image]][npm-url] [![Build Status][travis-image]][travis-url] [![Dependency Status][daviddm-image]][daviddm-url]

An electrode plugin that enables stateless CSRF protection using [JWT](https://github.com/auth0/node-jsonwebtoken) in Electrode, Express, Hapi, or Koa 2 applications.

## Why do we need this module?

CSRF protection is an important security feature, but in systems which don't have backend session persistence, doing CSRF token validation is tricky. Stateless CSRF support addresses this need.

## How do we validate requests?

***Double JWT CSRF tokens***

We rely on the fact that cross site requests can't set headers.

Two JWT CSRF tokens are generated on the server side with the same payload but different types (see below), one for the HTTP header, one for the cookie.

```js
headerPayload = { type: "header", UUID: "12345" };
cookiePayload = { type: "cookie", UUID: "12345" };
```

When a client makes a request, the JWT token must be sent in the headers.

On server side, both tokens are received, decoded, and validated to make sure the payloads match.

Disadvantage: relies on client making all request through AJAX.

## Install

```bash
$ npm install electrode-csrf-jwt
```
> You can use the `--save` option to update `package.json`

## Usage

### Options

`options`:

* `secret`: **Required**. A string or buffer containing either the secret for HMAC algorithms, or the PEM encoded private key for RSA and ECDSA.

Others are optional and follow the [same usage as jsonwebtoken](https://github.com/auth0/node-jsonwebtoken/blob/master/README.md#usage)

* `algorithm`
* `expiresIn`
* `notBefore`
* `audience`
* `subject`
* `issuer`
* `jwtid`
* `subject`
* `noTimestamp`
* `headers`

This module can be used with either [Electrode](#electrode), [Express](#express), [Hapi](#hapi), or [Koa 2](#koa-2).

### Electrode

#### Example `config/default.json` configuration

```json
{
  "plugins": {
    "electrode-csrf-jwt": {
      "options": {
        "secret": "shhhhh",
        "expiresIn": 60
      }
    }
  }
}
```

### Express

#### Example `app.js` configuration

```js
const csrfMiddleware = require("electrode-csrf-jwt").expressMiddleware;
const express = require("express");

const app = express();

const options = {
  secret: "shhhhh",
  expiresIn: 60
};

app.use(csrfMiddleware(options));
```

### Hapi

#### Example `server/index.js` configuration

```js
const csrfPlugin = require("electrode-csrf-jwt").register;
const Hapi = require("hapi");

const server = new Hapi.Server();
const options = {
  secret: "shhhhh",
  expiresIn: 60
};

server.register({register: csrfPlugin, options}, (err) => {
  if (err) {
    throw err;
  }
});
```

### Koa 2

#### Example `app.js` configuration

```js
const csrfMiddleware = require("electrode-csrf-jwt").koaMiddleware;
const Koa = require("koa");

const app = new Koa();

const options = {
  secret: "shhhhh",
  expiresIn: 60
};

app.use(csrfMiddleware(options));
```

Built with :heart: by [Team Electrode](https://github.com/orgs/electrode-io/people) @WalmartLabs.

[npm-image]: https://badge.fury.io/js/electrode-csrf-jwt.svg
[npm-url]: https://npmjs.org/package/electrode-csrf-jwt
[travis-image]: https://travis-ci.org/electrode-io/electrode-csrf-jwt.svg?branch=master
[travis-url]: https://travis-ci.org/electrode-io/electrode-csrf-jwt
[daviddm-image]: https://david-dm.org/electrode-io/electrode-csrf-jwt.svg?theme=shields.io
[daviddm-url]: https://david-dm.org/electrode-io/electrode-csrf-jwt
