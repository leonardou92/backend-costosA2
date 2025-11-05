const app = require('../scripts/api-server.cjs');

// Vercel may rewrite routes and strip the /api prefix when forwarding to
// a single function. Ensure the Express app always sees paths starting with
// /api so the existing route definitions (e.g. /api/summary) match.
module.exports = (req, res) => {
  try {
    if (!req.url.startsWith('/api')) {
      // preserve root (/) correctly
      req.url = '/api' + (req.url === '/' ? '' : req.url);
    }
  } catch (e) {
    // ignore and continue
  }
  return app(req, res);
};