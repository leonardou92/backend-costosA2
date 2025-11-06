const app = require('../scripts/api-server.cjs');

module.exports = (req, res) => {
  try {
    // keep query/path after /inventario
    const suffix = req.url === '/' ? '' : req.url;
    req.url = '/api/inventario' + suffix;
  } catch (e) {}
  return app(req, res);
};
