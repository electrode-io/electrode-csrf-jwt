"use strict";

const JwtTokenEngine = require("../../lib/jwt-token-engine");

describe("jwt-token-engine", () => {
  it("should fail verify bad tokens", () => {
    const engine = new JwtTokenEngine({ secret: "test 123" });
    const verify = engine.verify("foo", "bar");
    expect(verify.error, "should get error from verify").to.exist;
    expect(verify.error.message, "error should be BAD_TOKEN from verify").to.equal("BAD_TOKEN");
  });
});
