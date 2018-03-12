"use strict";

const UUID = require("uuid");
const simpleId = require("./simple-id-generator");

const defaultIdGenerators = {
  uuid: () => UUID.v4(),
  simple: () => simpleId()
};

module.exports = function getIdGenerator(uuidGen) {
  return typeof uuidGen === "function"
    ? uuidGen
    : defaultIdGenerators[uuidGen] || defaultIdGenerators.uuid;
};
