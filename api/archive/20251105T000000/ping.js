module.exports = (req, res) => {
  res.status(200).json({ ok: true, env: { VERCEL_URL: process.env.VERCEL_URL || null } });
};
