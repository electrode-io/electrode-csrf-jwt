"use strict";

const pkg = require("../../package.json");
const electrodeCsrf = require("../..");

describe("electrodeCsrf", function() {
  describe("hapiCreateToken", function() {
    it("should not call createToken if plugin doesn't have it", () => {
      const request = {
        plugins: {
          [pkg.name]: {
            test: "foo"
          }
        }
      };
      expect(electrodeCsrf.hapiCreateToken(request)).to.deep.equal({});
    });

    it("should return empty {} if request doesn't have the plugin", () => {
      expect(electrodeCsrf.hapiCreateToken({ plugins: {} })).to.deep.equal({});
    });
  });
});
