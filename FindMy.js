const { requestReports } = require("./src/request_reports");
const {
  generateKeys,
  getFindMyDataFromPrivateKey,
} = require("./src/generate_keys");

module.exports = {
  requestReports,
  generateKeys,
  getFindMyDataFromPrivateKey,
};
