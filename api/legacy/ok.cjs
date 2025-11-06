module.exports = (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.status(200).end(JSON.stringify({ ok: true, message: 'vercel api OK', env: { VERCEL_URL: process.env.VERCEL_URL || null } }));
};
