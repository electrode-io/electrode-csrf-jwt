"use strict";

/* eslint-disable */

var baseUrl = "http://dev.mysite.com:3000";
var defaultUseLocalStorage = true;
var useLocalStorage;

var HEADER_TOKEN; // save header token if use localStorage is off
var headerName = "x-csrf-jwt";
var firstPostHeaderName = "x-csrf-first-post";
var localHeaderSaveKey = "csrf-header-token";
var useLocalStorageFlagKey = "csrf-use-local-storage";
var initialHeaderTokenKey = "initial-csrf-header-token";

//
// Save CSRF use localStorage flag to localStorage and allow user to toggle it
//
function saveUseLocalStorageFlag() {
  if (window.localStorage) {
    window.localStorage.setItem(useLocalStorageFlagKey, useLocalStorage ? "true" : "");
  }
}

function initUseLocalStorageFlag() {
  if (useLocalStorage === undefined && window.localStorage) {
    var saveFlag = window.localStorage.getItem(useLocalStorageFlagKey);
    if (saveFlag !== null) {
      useLocalStorage = Boolean(saveFlag);
    } else {
      useLocalStorage = defaultUseLocalStorage;
      saveUseLocalStorageFlag();
    }
  }
}

function setUseLocalStorageStatus() {
  initUseLocalStorageFlag();
  var statusElm = document.getElementById("useLocalStorage");
  if (statusElm) {
    statusElm.innerText = useLocalStorage ? "on" : "off";
  }
}

function toggleUseLocalStorage() {
  useLocalStorage = !useLocalStorage;
  setUseLocalStorageStatus();
  saveUseLocalStorageFlag();
}

//
// Save header token into an internal state or to localStorage if it is turned on
//
function saveHeaderToken(token) {
  if (useLocalStorage && window.localStorage) {
    window.localStorage.setItem(localHeaderSaveKey, token);
    window.localStorage.removeItem(initialHeaderTokenKey);
  } else {
    HEADER_TOKEN = token;
  }
}

//
// Retrieve header token from an internal state or the localStorage if it is turned on
//
function getHeaderToken() {
  if (!useLocalStorage || !window.localStorage) return { token: HEADER_TOKEN };

  var initialHeaderToken = window.localStorage.getItem(initialHeaderTokenKey);
  if (initialHeaderToken !== null) {
    console.log("Using initial CSRF header token");
    window.localStorage.removeItem(initialHeaderTokenKey);
    return { token: initialHeaderToken, firstPost: true };
  }

  return { token: window.localStorage.getItem(localHeaderSaveKey) };
}

//
// Save header token from AJAX (fetch) response
//
function saveResponseHeader(res) {
  var h = res.headers.get(headerName);
  if (h) {
    console.log("csrf header token", h);
    saveHeaderToken(h);
  } else {
    console.log("no csrf header token received");
  }
}

function testPost(error, retry) {
  console.log("testPost");
  var headerToken = "";

  var headers = {
    "content-type": "application/json"
  };

  // simulate invalid CSRF token to trigger error response
  if (!error) {
    var header = getHeaderToken();
    headers[headerName] = header.token;
    if (header.firstPost) {
      headers[firstPostHeaderName] = "1";
    }
  } else {
    headers[headerName] = "";
  }

  return fetch(baseUrl + "/api/1", {
    body: "{}",
    headers,
    // must set credentials for browser to send cookies
    // https://github.com/github/fetch#sending-cookies
    credentials: "same-origin",
    mode: "cors",
    method: "POST"
  }).then(res => {
    saveResponseHeader(res);
    // if response status is not 200, then retry once
    if (res.status !== 200 && !retry) {
      console.log("Response status is not 200, retrying.");
      return testPost(false, true);
    }
    return res.json().then(data => {
      console.log("testPost data", data);
    });
  });
}

function testGet() {
  console.log("testGet");
  return fetch(baseUrl + "/api/2", {
    credentials: "same-origin"
  }).then(res => {
    saveResponseHeader(res);
    return res.json().then(data => {
      console.log("testGet data", data);
    });
  });
}
