# Demo using Electrode Stateless CSRF In Browser

This is a simple demo webapp for the Electrode Stateless CSRF in [Hapi].

It consists of three parts:

1.  A NodeJS server using [electrode-server] and integrated with the Hapi CSRF plugin.
2.  A JavaScript file for making AJAX GET/POST requests with CSRF protection from the browser.
3.  A very simple HTML page for interaction

# Setup

The demo expects the following domain name aliases setup for your localhost.

* `dev.mysite.com` - Your trusted site
* `cdn.mycdn.com` - Your trusted CDN servers (for serving the JavaScript file)
* `dev.badsite.com` - The malicious site

If you are on \*nix and you can `sudo`, then you can edit your `/etc/hosts` file and add the following lines to simulate them:

```
127.0.0.1   dev.mysite.com
127.0.0.1   cdn.mycdn.com
127.0.0.1   dev.badsite.com
```

# Running

To start the demo, run `npm run demo`.

You should see something similar to the following:

```
$ npm run demo

> electrode-csrf-jwt@1.3.1 demo /dev/electrode-csrf-jwt
> node demo/server

staticPaths Plugin: static files route prefix "" path prefix "demo" at routes js,images,html

Hapi.js server running at http://L-SB8H1M2G8W-M:3000
```

Now point your browser to `http://dev.mysite.com:3000`, open the console in dev tools, and click the buttons to try the GET or POST AJAX requests.

You can also point your browser to `http://dev.badsite.com:3000` and observe the browser refusing to let the POST request through because of the HTTP header not allowed error.

To test multi tab, open another browser tab to `http://dev.mysite.com:3000`, make sure "use localStorage" is `on` for both, and click the POST button alternatively in the two tabs. Observe that the requests will go through successfully.

# The Demo

Other than the basic stateless CSRF demonstration, the following are also implemented:

* Making first POST call work
* Multi browser tab support

## Demo Only Changes

In order to demo some features, the NodeJS server disabled these security settings:

* Turn off [HTTP Only] flag in the token cookie to allow the code to inspect and show it.
* Enable [CORS] and override [Hapi]'s internal HTTP OPTIONS for the routes to avoid the browser refusing requests from `badsite.com` due to CORS check, but then refuse it due to HTTP header not allowed check.

**_Make sure you don't do these in your app._** Please do not copy and paste code from the demo into production app.

## Issues

To keep your application as secured as possible, it's recommended that your JavaScript making the AJAX requests keep the CSRF header token in an internal variable.

There are two issues with doing that however:

1.  Your first request must be GET to prime the tokens.
2.  Your application doesn't work across browser tabs.

## Solutions

If you implement retry, then both issues should be taken care of automatically.

To solve the issues without relying on retry, a trusted and secured channel for sharing the header token is required. Given this happens on the user's browser, it's tricky. Ultimately we have to go by the standards but still depend on the actual implemention in different browsers.

In this demo, the header token is stored into [`window.localStorage`] in the following keys:

* `initial-csrf-header-token` - store the header token that's dropped by the first page for use if first request has to be POST.
* `csrf-header-token` - store the normal header token acquired after each request.

### First POST

If you want to limit the routes that allow first POST calls, then you should do the following:

* In your request, set the HTTP header `x-csrf-first-post` to `"1"`.
* On the server side, set the route config option `allowFirstPost` to `true` (Hapi only for now)

Other routes that doesn't have the `allowFirstPost` set to true would refuse such requests.

### Implications

Regardless of how secured `window.localStorage` is, by using it, you expand the attackable area of your application. So you should evaluate the implications before using it.

Another option is to open an `iframe` and use message passing to store the header token into that in order to shared it across tabs. Of course there are other potential attack vectors for that as well.

However, the question is, what is the consequence even if some malicious code found a way to access your application's `window.localStorage`? In the end, these two restrictions are still the most critical:

* cross site scripts can't access cookies, especially [HTTP only] ones.
* cross site scripts can't set HTTP headers

[hapi]: https://www.npmjs.com/package/hapi
[electrode-server]: https://www.npmjs.com/package/electrode-server
[http only]: https://www.owasp.org/index.php/HttpOnly
[`window.localstorage`]: https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage
[cors]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
