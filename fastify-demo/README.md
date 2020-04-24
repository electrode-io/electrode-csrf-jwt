# Demo using Electrode Stateless CSRF In Browser

This is a simple demo webapp for the Electrode Stateless CSRF in [Fastify].

It consists of three parts:

1.  A NodeJS server using [Fastify] and integrated with the Fastify CSRF plugin.
2.  A JavaScript file for making AJAX GET/POST requests with CSRF protection from the browser.
3.  A very simple HTML page for interaction

# Setup

The demo expects the following domain name aliases setup for your localhost.

* `dev.mysite.com` - Your trusted site
* `dev.badsite.com` - The malicious site

If you are on \*nix and you can `sudo`, then you can edit your `/etc/hosts` file and add the following lines to simulate them:

```
127.0.0.1   dev.mysite.com
127.0.0.1   dev.badsite.com
```

# Running

To start the demo,

```
$ cd fastify-demo
$ npm i
$ npm start
```

Now point your browser to `http://dev.mysite.com:3000`, open the console in dev tools, and click the buttons to try the GET or POST AJAX requests.

You can also point your browser to `http://dev.badsite.com:3000` and observe the browser refusing to let the POST request through because of the missing token.

## Demo Only Changes

In order to demo some features, the NodeJS server disabled these security settings:

* Enable [CORS] to avoid the browser refusing requests from `badsite.com` due to CORS check.

**_Make sure you don't do these in your app._** Please do not copy and paste code from the demo into production app.

[Fastify]: https://www.fastify.io/docs/latest/
[cors]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
