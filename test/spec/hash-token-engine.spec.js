"use strict";

const crypto = require("crypto");
const HashTokenEngine = require("../../lib/hash-token-engine");
const xstdout = require("xstdout");

describe("hash-token-engine", () => {
  const secret = crypto.randomBytes(1024);

  it("should warn about secret shorter than 1024 bytes", () => {
    const intercept = xstdout.intercept(true);
    new HashTokenEngine({});
    new HashTokenEngine({ secret: "short secret" });
    intercept.restore();
    expect(intercept.stderr[0]).to.contains("you should set a 1024+ bytes secret");
    expect(intercept.stderr[1]).to.contains("you should set a 1024+ bytes secret");
  });

  it("should fail verify bad tokens", () => {
    const engine = new HashTokenEngine({ secret });
    const now = Math.floor(Date.now() / 1000);
    const badPayload = Buffer.from("foo").toString("base64");
    const tokens = engine._encode(`1.${now}.1h.${badPayload}.12345`, "bar");
    const verify = engine.verify(tokens.header, tokens.cookie);
    expect(verify.error, "should get error from verify").to.exist;
    expect(verify.error.message, "error should be BAD_TOKEN from verify").to.equal("BAD_TOKEN");
  });
});
