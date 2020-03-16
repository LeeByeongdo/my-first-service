"use strict";
const jwt = require("jsonwebtoken");
const sha256 = require("js-sha256").sha256;

module.exports.hello = async (event, context, callback) => {
  const request = event.Records[0].cf.request;
  const headers = request.headers;

  let isEmployee = false;

  // from csr
  const authorizationHeader = headers["authorization"]
    ? headers["authorization"][0].value
    : "";
  if (authorizationHeader && authorizationHeader.split(" ").length > 1) {
    const token = authorizationHeader.split(" ")[1];

    try {
      const decoded = jwt.verify(
        token,
        "1234567890123456789012345678901234567890123456789012345678901234"
      );
      isEmployee = decoded.isEmployee;
    } catch (e) {
      // eslint-disable-next-line no-console
      console.log(e);
      isEmployee = false;
    }
  } else {
    // from ssr
    const sessionHeader = headers["usersession"]
      ? headers["usersession"][0].value
      : "";
    if (sessionHeader && sessionHeader.length > 3) {
      const checksumKey =
        "1234567890123456789012345678901234567890123456789012345678901234";
      const split = sessionHeader.split("|");
      const sid = split[0];
      const option = Number(split[1]);
      const timestamp = split[2];
      const checksum = split[3];

      if (
        sha256(`${sid}|${option}|${timestamp}${checksumKey}`).toUpperCase() ===
        checksum
      ) {
        isEmployee = (option & 3) === 3;
      }
    }
  }

  headers["isEmployee"] = [{ key: "isEmployee", value: String(isEmployee) }];

  callback(null, request);
};
