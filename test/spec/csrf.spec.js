"use strict";

const crypto = require("crypto");
const CSRF = require("../../lib/csrf");

describe("csrf driver", function() {
  const secret = crypto.randomBytes(1024);

  it("should use hash token engine if options set it", () => {
    const csrf = new CSRF({ tokenEngine: "hash", secret });
    expect(csrf.engine.constructor.name).to.equal("HashTokenEngine");
  });
});
