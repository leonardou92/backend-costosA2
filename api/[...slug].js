const app = require('../scripts/api-server.cjs');

module.exports = (req, res) => {
  // Express app is a request handler; forward the request to it.
  return app(req, res);
};