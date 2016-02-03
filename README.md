# csrf-jwt

Express middleware / Hapi plugin that allows you to authenticate HTTP requests using JWT in your Express or Hapi applications.

This is built on top of [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken).

## Why do we need this module

CSRF protection is an important security feature we need.

Due to the fact that walmart.com webapps don't have a backend session storage, doing CSRF token validation is tricky.

We need stateless CSRF validation.

## How do we validate CSRF

***Double JWT CSRF tokens***

We rely on the fact that cross site requests can't set headers.

Server side generates two JWT CSRF tokens with the same payload but different types (see below), one for header, one for cookie.

```js
headerPayload = { type: "header", UUID: "12345" };
cookiePayload = { type: "cookie", UUID: "12345" };
```

When client makes a request, it has to send the JWT token in headers.

On server side, we should receive both tokens. After decoding and validating them, we make sure payload from both matches.

Disadvantage: relies on client making all request through AJAX.

## Install

```bash
$ npm install @walmart/csrf-jwt
```

## Usage

This module can be used with either Express or Hapi.

### Express Middleware

#### app.use(csrfMiddleware(options));

`options`:

* `secret`: **Required**. A string or buffer containing either the secret for HMAC algorithms, or the PEM encoded private key for RSA and ECDSA.

Others are optional, same usage as [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken/blob/master/README.md#usage)

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

#### Example

```js
const csrfMiddleware = require("@walmart/csrf-jwt").expressMiddleware;
const express = require("express");

const app = express();

const options = {
  secret: "shhhhh",
  expiresIn: 60
};

app.use(csrfMiddleware(options));
```

### Hapi plugin

#### server.register({register: csrfPlugin, options}, [callback])

`options`: same as above.

#### Example

```js
const csrfPlugin = require("@walmart/csrf-jwt").register;
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
