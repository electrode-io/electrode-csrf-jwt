# csrf-jwt

Express middleware / Hapi plugin that allows you to authenticate HTTP requests using JWT in your Express or Hapi applications.

This is built on top of [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken).

## Why do we need this

If your application has a completely stateless server side, without session or storage, there's no way to prevent CSRF using traditional methods.

With this module, we encode the user's IP address into a JWT, return it to the client. And to validate, we decode the JWT and verify the IP address.

This way there's no session needed at all.

## Install

```bash
$ npm install csrf-jwt
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
const csrfMiddleware = require("../").expressMiddleware;
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
const csrfPlugin = require("../").hapiPlugin;
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

