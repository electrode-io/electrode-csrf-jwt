"use strict";

/* eslint-disable prefer-template, no-magic-numbers */

/*
 *
 * A very simple and reasonably unique ID generator using Math.random and Date.now.
 *
 * IDs look like this: 2s53xp2feox_jeohy54s
 *
 * Given that Math.random is not a very good random number generator, the chance of collison
 * is there, so choose this carefully.
 *
 * Note that the uuid module being used depends on the high quality random generator
 * https://nodejs.org/docs/latest-v8.x/api/crypto.html#crypto_crypto_randombytes_size_callback
 * which depends on libuv's threadpool to get entropy and could have
 * "surprising and negative performance implications for some applications"
 *
 */

module.exports = () => {
  return (
    Math.random()
      .toString(36)
      .substr(2) +
    "_" +
    Date.now().toString(36)
  );
};
