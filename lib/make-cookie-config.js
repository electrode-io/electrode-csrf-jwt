"use strict";

module.exports = function(defaultConfig, userConfig) {
  const cookieConfig = Object.assign({}, defaultConfig, userConfig);

  Object.keys(cookieConfig).forEach(x => {
    if (cookieConfig[x] === undefined || cookieConfig[x] === null) {
      delete cookieConfig[x];
    }
  });

  return cookieConfig;
};
