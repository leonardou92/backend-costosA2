const app = require('../scripts/api-server.cjs');

module.exports = (req, res) => {
  return app(req, res);
};