const jwt = require('jsonwebtoken');
const Order = require('./models/order');

function authenticate(token, secret) {
  return jwt.verify(token, secret, { algorithms: ['HS256'], audience: 'orders-api', issuer: 'https://id.orders.test' });
}

module.exports = (app) => {
  app.post('/orders', async (req, res) => {
    const { item, quantity } = req.body;
    const order = await Order.create({ item, quantity, owner: req.user.id });
    res.json(order);
  });
  app.put('/orders/:id', async (req, res) => {
    const order = await Order.findById(req.params.id);
    order.quantity = req.body.quantity;
    res.json(await order.save());
  });
};
