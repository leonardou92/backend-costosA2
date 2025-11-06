const app = require('../scripts/api-server.cjs');

module.exports = (req, res) => {
  try {
    req.url = '/api/health' + (req.url === '/' ? '' : req.url);
  } catch (e) {}
  return app(req, res);
};
