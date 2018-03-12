"use strict";

const JwtTokenEngine = require("../../lib/jwt-token-engine");

describe("jwt-token-engine", () => {
  it("should create tokens", () => {
    const engine = new JwtTokenEngine({ secret: "test 123" });
    const tokens = engine.create();
    expect(tokens.header, "Should have header token").to.be.ok;
    expect(tokens.cookie, "Should have cookie token").to.be.ok;
  });

  it("should verify tokens", () => {
    const engine = new JwtTokenEngine({ secret: "test 123" });
    const tokens = engine.create();
    expect(tokens.header, "Should have header token").to.be.ok;
    expect(tokens.cookie, "Should have cookie token").to.be.ok;
    const verify = engine.verify(tokens.header, tokens.cookie);
    expect(verify.error, "created token didn't verify").to.be.undefined;
  });

  it("should fail verify bad tokens", () => {
    const engine = new JwtTokenEngine({ secret: "test 123" });
    const verify = engine.verify("foo", "bar");
    expect(verify.error, "should get error from verify").to.exist;
    expect(verify.error.message, "error should be BAD_JWT from verify").to.equal("BAD_JWT");
  });

  it("should fail verify invalid tokens", () => {
    const engine = new JwtTokenEngine({ secret: "test 123" });

    const tokens1 = engine.create();
    const tokens2 = engine.create();
    const verify = engine.verify(tokens1.header, tokens2.cookie);
    expect(verify.error, "should get error from verify").to.exist;
    expect(verify.error.message, "error should be INVALID_JWT from verify").to.equal("INVALID_JWT");
  });

  it("should fail verify for expired tokens", () => {
    const engine = new JwtTokenEngine({ secret: "test 123" });
    const tokens = engine.create({}, { expiresIn: "0s" });
    const verify = engine.verify(tokens.header, tokens.cookie);
    expect(verify.error, "should get error from verify").to.exist;
    expect(verify.error.message, "error should be BAD_JWT from verify").to.equal("BAD_JWT");
  });

  it("should fail verify for missing tokens", () => {
    const engine = new JwtTokenEngine({ secret: "test 123" });
    const verify = engine.verify("", "");
    expect(verify.error, "should get error from verify").to.exist;
    expect(verify.error.message, "error should be MISSING_JWT from verify").to.equal("MISSING_JWT");
  });
});
