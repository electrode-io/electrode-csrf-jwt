# Electrode CSRF JWT

[![NPM version][npm-image]][npm-url] [![Build Status][travis-image]][travis-url] [![Dependency Status][daviddm-image]][daviddm-url]

An electrode plugin that enables stateless [CSRF] protection using [JWT](https://github.com/auth0/node-jsonwebtoken) in Electrode, Express, Hapi, or Koa 2 applications.

## Why do we need this module?

[CSRF] protection is an important security feature, but in systems which don't have backend session persistence, doing CSRF token validation is tricky. Stateless CSRF support addresses this need.

## How do we validate requests?

The technique used by this module is similar to the CSRF [double submit cookie prevention technique].

These techniques rely on these two restrictions by the browsers:

1.  cross site scripts can't read/modify cookies.
2.  cross site scripts can't set headers.

The [double submit cookie prevention technique] rely on the fact that a unique token in cookie must match a token attached in a hidden form submit field. Since XSS cannot change cookies, the check prevents CSRF attacks.

> Note that the first restriction has some loopholes and thus the double submit cookie technique is not completely secured. See https://www.owasp.org/images/3/32/David_Johansson-Double_Defeat_of_Double-Submit_Cookie.pdf

### Double JWT CSRF tokens

For use with [XMLHttpRequest], we extend the technique by using two JWT tokens for validation. One token in the cookies and the other in the HTTP headers. Since XSS cannot set HTTP headers also, it strengthens the security further.

So two JWT CSRF tokens are generated on the server side with the same payload but different types (see below), one for the HTTP header, one for the cookie.

```js
headerPayload = { type: "header", UUID: "12345" };
cookiePayload = { type: "cookie", UUID: "12345" };
```

When a client makes a request, the JWT tokens must be sent in the cookie and headers.

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
* `shouldSkip`: **Optional** A callback that takes the `request` (or context for Koa) object and returns `true` if it wants completely skip the CSRF JWT middleware/plugin for the given `request`
* `skipCreate`: **Optional** A callback that takes the `request` (or context for Koa) object and returns `true` if it wants the CSRF JWT to skip creating the token for the given `request`
* `skipVerify`: **Optional** A callback that takes the `request` (or context for Koa) object and returns `true` if it wants the CSRF JWT to skip verifying for the given `request`
* `cookieConfig`: **Optional** An object with extra configs for setting the JWT cookie token. Values set to `undefined` or `null` will delete the field from the default cookie config.
* `uuidGen`: **Optional** A string of `uuid` or `simple` to select the unique ID generator, or a callback to generate the ID. See [uuidGen Option](#uuidgen-option) for details.

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

#### uuidGen Option

This module by default use the [uuid] module to generate the uuid used in the JWT token.

However, [uuid] uses [crypto.randomBytes](https://nodejs.org/docs/latest-v8.x/api/crypto.html#crypto_crypto_randombytes_size_callback), which "uses libuv's threadpool, which can have surprising and negative performance implications for some applications".

You can set `options.uuidGen` as follows to select another UUID generator:

* `"simple"` - select a [simple](./lib/simple-id-generator.js) one from this module
* `"uuid"` - the default: uses [uuid]
* callback - your own function that returns the ID

### Electrode

#### Example `config/default.js` configuration

```js
{
  "plugins": {
    "electrode-csrf-jwt": {
      "options": {
        "secret": "shhhhh",
        "expiresIn": 60,
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

server.register({ register: csrfPlugin, options }, err => {
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
  expiresIn: 60,
  shouldSkip: context => {
    // return true to skip CSRF JWT for given context
    return false;
  },
  skipCreate: context => {
    // return true to skip creating CSRF JWT Token for given context
    return false;
  },
  skipVerify: context => {
    // return true to skip verifying CSRF JWT Token for given context
    return false;
  }
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
[uuid]: https://www.npmjs.com/package/uuid
[double submit cookie prevention technique]: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookie
[xmlhttprequest]: https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest
[csrf]: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
