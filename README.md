# Electrode Stateless CSRF

[![NPM version][npm-image]][npm-url] [![Build Status][travis-image]][travis-url] [![Dependency Status][daviddm-image]][daviddm-url]

An electrode plugin that enables stateless [CSRF] protection using [JWT](https://github.com/auth0/node-jsonwebtoken) in Electrode, Express, Hapi, or Koa 2 applications.

## Why do we need this module?

[CSRF] protection is an important security feature, but in systems which don't have backend session persistence, validation is tricky. Stateless CSRF support addresses this need.

Please see the [demo](./demo) for a sample of using this in a web application with Hapi NodeJS server.

## How do we validate requests?

CSRF attacks can be bad when a malicious script can make a request that can perform harmful operations through the user (victim)'s browser, attaching user specific and sensitive data in the cookies.

To prevent it, the technique used by this module is similar to the CSRF [double submit cookie prevention technique], and relies on these two restrictions by the browsers:

1.  cross site scripts can't read/modify cookies.
2.  cross site scripts can't set headers.

The [double submit cookie prevention technique] rely on the fact that a unique token in cookie must match a token attached in a hidden form submit field. Since XSS cannot change cookies, the check prevents CSRF attacks.

> Note that the first restriction has some loopholes and thus the double submit cookie technique is not completely secured. See https://www.owasp.org/images/3/32/David_Johansson-Double_Defeat_of_Double-Submit_Cookie.pdf

### Double JWT CSRF tokens

For use with [XMLHttpRequest] and [fetch], we extend the technique by using two JWT tokens for validation. One token in the cookies and the other in the HTTP headers. Since XSS cannot set HTTP headers also, it strengthens the security further.

So two JWT CSRF tokens are generated on the server side with the same payload but different types (see below), one for the HTTP header and one for the cookie. This makes two different tokens but uniquely paired with each other by the UUID.

```js
headerPayload = { type: "header", UUID: "12345" };
cookiePayload = { type: "cookie", UUID: "12345" };
```

When a client makes a request, the JWT tokens must be sent in the cookie and headers, both are channels that cross site scripts have no control over.

Further, we set the cookie to be [HTTP Only] so any browser that supports it would prevent **any** scripts from accessing it at all.

On the server side, the tokens are decoded and validated to pair with each other to identify legitimate requests.

If a malicious script somehow manages to alter one of the tokens passed through the cookie or HTTP header, then they will not match. In order to forge a request on the victim's behalf, both restrictions must be circumvented.

### Issues

There are some issues with our technique.

1.  We rely on client making all request through AJAX because of the requirement to set HTTP header.

2.  First call has to be a GET to prime the header token. Since the code that use [XMLHttpRequest] or [fetch] need to first acquire valid tokens through a non-mutable request like HTTP GET to populate its internal state, so if your first call has to be POST, then it's tricky.

3.  Similar to the cause in #2 above, multiple browser tabs could run into token mismatches, since cookies are shared across tabs but each tab's code keeps its own internal token for the HTTP header.

Issue 1 is the essential of how the technique works so that's just its limitation.

Issue 2 and 3 are tricky, but there are some solutions. See [demo](./demo/README.md) for reference.

## Install

```bash
$ npm install --save electrode-csrf-jwt
```

# Usage and Integration

## Browser Integration

To protect your AJAX requests from the browser, your JavaScript code need to first make a GET call to acquire an initial pair of CSRF tokens. The [HTTP only] cookie token is dropped automatically. Your code has to extract the header token and save it to an internal variable.

In subsequent requests (GET or POST), you have to attach the header token acquired in the HTTP header `x-csrf-jwt`.

If you receive an error, then you should take the token from the error response and retry one more time.

### Full Demo

You can reference a sample [demo](./demo/README.md) to use this for your webapp.

## Serverside Integration

This module includes a plugin for [Hapi] (v16 or lower) and middleware for [express] and [koa]. They can be used with the following:

- [electrode-server](#electrode-server)
- [Express](#express)
- [Hapi](#hapi)
- [Koa 2](#koa-2)
- [Fastify](#fastify)

### Options

First the options. Regardless of which server framework you use, the options remains the same when you pass it to the plugin or middleware.

#### Required Fields

- `secret`: A string or buffer containing either the secret for HMAC algorithms, or the PEM encoded private key for RSA and ECDSA.

#### Optional Fields

- `cookieName`: A string to use as name for setting the cookie token. Default: `x-csrf-jwt`
- `headerName`: A string to use as name for setting the header token. Default: **cookieName**
- `cookieConfig`: An object with extra configs for setting the JWT cookie token. Values set to `undefined` or `null` will delete the field from the default cookie config. See the respective server framework for info on what their cookie config should be.
  - `path`: Cookie path
  - `isSecure`: Whether cookie is pass secure of not
  - `httpOnly`: HTTP only.
- `tokenEngine`: **Experimental** A string that specifies the token engine. Either the default [`"jwt"`](./lib/jwt-token-engine.js) or [`"hash"`](./lib/hash-token-engine.js).

#### Optional `uuidGen` Field

This module by default uses the [uuid] module. However, it uses [crypto.randomBytes](https://nodejs.org/docs/latest-v8.x/api/crypto.html#crypto_crypto_randombytes_size_callback), which "uses libuv's threadpool, which can have surprising and negative performance implications for some applications".

If that's an issue, then you can set the `uuidGen` option as follows to select another UUID generator:

- `"simple"` - select a [simple](./lib/simple-id-generator.js) one from this module
- `"uuid"` - the default: uses [uuid]
- **function** - your own function that returns the ID, which should be a URL safe string

#### Optional Skip Callbacks

The following should be functions that take the `request` (or `context` for Koa) object and return `true` to skip their respective step for the given `request`:

- `shouldSkip`: Completely skip the CSRF middleware/plugin
- `skipCreate`: Skip creating the tokens for the response
- `skipVerify`: Skip verifying the incoming tokens

#### JWT specific optional fields

Others are optional and follow the [same usage as jsonwebtoken](https://github.com/auth0/node-jsonwebtoken/blob/master/README.md#usage) if the `tokenEngine` is `jwt`.

- `algorithm`
- `expiresIn`
- `notBefore`
- `audience`
- `subject`
- `issuer`
- `jwtid`
- `subject`
- `noTimestamp`
- `headers`

### Electrode Server

[electrode-server] is a top level wrapper for [Hapi]. You can use the hapi-plugin in [electrode-server] by setting your configuration.

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

### Fastify

Please register `fastify-cookie` plugin before `electrode-csrf-jwt` to add cookie support with fastify.

#### Example `server.js` configuration

```js
const csrfPlugin = require("electrode-csrf-jwt").fastify;
const Fastify = require("fastify");
const fastifyCookie = require("fastify-cookie");

csrfPlugin[Symbol.for("skip-override")] = true;

const server = Fastify();
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

server.register(fastifyCookie).register(csrfPlugin, options);
server.listen(3000, err => {
  if (err) throw err;
  console.log(`Server listening at http://localhost:${fastify.server.address().port}`);
});
```

### HTTPS and cookies

When running in HTTPS, you will need to specify the cookie with `secure=true`. Use the `cookieConfig` option

```js
{
   "cookieConfig": {
     "isSecure": true
   }
}
```

### Client-side fetch

When doing client-side fetch to the server, it is preferable to use [electrode-fetch](https://gecgithub01.walmart.com/electrode/electrode-fetch).  
Electrode-fetch will look for the `x-csrf-jwt` header from responses and use it as the new JWT token on subsequent fetches.  
If you use your own fetch function, you will have to handle this yourself.




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
[fetch]: https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API
[csrf]: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
[hapi]: https://www.npmjs.com/package/hapi
[express]: https://www.npmjs.com/package/express
[koa]: https://www.npmjs.com/package/koa
[electrode-server]: https://www.npmjs.com/package/electrode-server
[http only]: https://www.owasp.org/index.php/HttpOnly
