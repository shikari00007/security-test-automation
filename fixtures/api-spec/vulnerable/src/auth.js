const jwt = require('jsonwebtoken');
const Order = require('./models/order');

function authenticate(token, secret) {
  return jwt.verify(token, secret, { algorithms: ['HS256'], ignoreExpiration: true });
}

function authenticateNoAud(token, secret) {
  return jwt.verify(token, secret, { algorithms: ['HS256'] });
}

module.exports = (app) => {
  app.post('/orders', async (req, res) => {
    const order = await Order.create(req.body);
    res.json(order);
  });
  app.put('/orders/:id', async (req, res) => {
    const order = await Order.findById(req.params.id);
    Object.assign(order, req.body);
    res.json(await order.save());
  });
};
