const mongoose = require('mongoose')

const wallet = new mongoose.Schema(
  {
    address: { type: String, required: true },
    type: { type: String, required: true },
    network: { type: String, required: true },
  }
)
const Wallet = mongoose.models.Wallet || mongoose.model('Wallet', wallet)
module.exports = Wallet