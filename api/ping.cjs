module.exports = (req, res) => {
  res.status(200).json({ ok: true, now: Date.now(), env: { VERCEL_URL: process.env.VERCEL_URL || null } });
};