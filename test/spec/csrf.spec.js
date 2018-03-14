"use strict";

const crypto = require("crypto");
const CSRF = require("../../lib/csrf");

describe("csrf driver", function() {
  const secret = crypto.randomBytes(1024);

  it("should use hash token engine if options set it", () => {
    const csrf = new CSRF({ tokenEngine: "hash", secret });
    expect(csrf.engine.constructor.name).to.equal("HashTokenEngine");
  });

  it("should create tokens for GET", done => {
    const csrf = new CSRF({ secret });
    const request = {};
    csrf.process(
      {
        request,
        method: "get",
        create: () => (request.create = true),
        verify: () => {
          throw new Error("don't expect verify to get called");
        },
        continue: () => {
          expect(request.create, "Must call create").to.equal(true);
          done();
        }
      },
      {}
    );
  });

  it("should verify and then create tokens for POST", done => {
    const csrf = new CSRF({ secret });
    const request = {};
    csrf.process(
      {
        request,
        method: "post",
        create: () => (request.create = true),
        verify: () => {
          request.verify = true;
          return {};
        },
        continue: () => {
          expect(request.create, "Must call create").to.equal(true);
          expect(request.verify, "Must call verify").to.equal(true);
          done();
        }
      },
      {}
    );
  });

  it("should fail if verify returns error for POST", done => {
    const csrf = new CSRF({ secret });
    const request = {};
    csrf.process(
      {
        request,
        method: "post",
        create: () => (request.create = true),
        verify: () => {
          request.verify = true;
          return { error: new Error("test fail verify") };
        },
        continue: () => {
          throw new Error("don't expect continue to be called");
        },
        error: verify => {
          expect(request.create, "Must call create").to.equal(true);
          expect(request.verify, "Must call verify").to.equal(true);
          done();
        }
      },
      {}
    );
  });

  it("should completely skip if routeConfig.shouldSkip is true", done => {
    const csrf = new CSRF({ secret });
    const request = {};
    csrf.process(
      {
        request,
        method: "post",
        create: () => {
          throw new Error("don't expect create to get called");
        },
        verify: () => {
          throw new Error("don't expect verify to get called");
        },
        continue: () => {
          done();
        }
      },
      { shouldSkip: true }
    );
  });

  it("should skip verify if routeConfig.skipVerify is true", done => {
    const csrf = new CSRF({ secret });
    const request = {};
    csrf.process(
      {
        request,
        method: "post",
        create: () => {
          request.create = true;
        },
        verify: () => {
          throw new Error("don't expect verify to get called");
        },
        continue: () => {
          expect(request.create, "expect create to be called").to.equal(true);
          done();
        }
      },
      { skipVerify: true }
    );
  });

  it("should not create tokens for GET if routeConfig.skipCreate is true", done => {
    const csrf = new CSRF({ secret });
    const request = {};
    csrf.process(
      {
        request,
        method: "get",
        create: () => {
          throw new Error("don't expect create to get called");
        },
        verify: () => {
          throw new Error("don't expect verify to get called");
        },
        continue: () => {
          done();
        }
      },
      { skipCreate: true }
    );
  });

  it("should verify tokens created by its create", () => {
    const csrf = new CSRF({ secret });
    const tokens = csrf.create();
    const verify = csrf.verify(tokens.header, tokens.cookie);
    expect(verify.error, "verify should pass").to.not.exist;
  });

  it("should fail first post if a route doesn't allow it", done => {
    const csrf = new CSRF({ secret });
    const request = {};
    csrf.process(
      {
        request,
        method: "post",
        firstPost: true,
        create: () => {
          request.create = true;
        },
        verify: () => {
          request.verify = true;
          return {};
        },
        continue: () => {
          throw new Error("don't expect continue to be called");
        },
        error: verify => {
          expect(request.create, "must have called create").to.equal(true);
          expect(request.verify, "must have called verify").to.equal(true);
          done();
        }
      },
      {}
    );
  });

  it("should accept first post if a route allows it", done => {
    const csrf = new CSRF({ secret });
    const request = {};
    csrf.process(
      {
        request,
        method: "post",
        firstPost: true,
        create: () => {
          request.create = true;
        },
        verify: () => {
          request.verify = true;
          return {};
        },
        continue: () => {
          expect(request.create, "must have called create").to.equal(true);
          expect(request.verify, "must have called verify").to.equal(true);
          done();
        },
        error: () => {
          throw new Error("don't expect error to be called");
        }
      },
      { allowFirstPost: true }
    );
  });
});
