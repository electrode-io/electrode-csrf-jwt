"use strict";

const baseUrl = "http://dev.mysite.com:3000";
const headerName = "x-csrf-jwt";
let HEADER_TOKEN;

const saveResponseHeader = res => {
  const h = res.headers.get(headerName);
  if (h) {
    HEADER_TOKEN = res.headers.get(headerName);
  } else {
    console.log("no csrf header token received");
  }
};

const testPost = () => {
  console.log("testPost");
  fetch(baseUrl + "/testPost", {
    body: "{'test':'world'}",
    method: "POST",
    headers: {
      [headerName]: HEADER_TOKEN
    }
  }).then(res => {
    console.log(res);
  });
};

const testGet = () => {
  console.log("testGet");
  fetch(baseUrl + "/getTokens").then(res => {
    console.log(res);
    saveResponseHeader(res);
  });
};
