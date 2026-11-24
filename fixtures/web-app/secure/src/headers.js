const ALLOWED = new Set(['https://app.example.org']);
module.exports = function corsHeaders(req, res, next) {
  const origin = req.headers.origin;
  if (ALLOWED.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
};
