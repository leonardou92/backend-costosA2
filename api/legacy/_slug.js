// [...slug].js original copied to legacy/_slug.js for archive
const app = require('../scripts/api-server.cjs');

// Ensure paths forwarded to Express include /api prefix so existing
// route definitions match regardless of how the platform forwards the URL.
module.exports = (req, res) => {
  try {
    if (!req.url.startsWith('/api')) {
      req.url = '/api' + (req.url === '/' ? '' : req.url);
    }
  } catch (e) {}
  return app(req, res);
};
