const app = require('../scripts/api-server.cjs');

module.exports = (req, res) => {
  try {
    // Ensure Express sees /api prefix
    if (!req.url.startsWith('/api')) req.url = '/api' + (req.url === '/' ? '' : req.url);
  } catch (e) {}
  return app(req, res);
};