const mongoose = require('mongoose');

const botPurchaseSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    botId: { type: String, required: true }, // e.g., 'VIP I', 'TradingBot_X'
    amount: { type: Number, required: true },
    walletAddress: { type: String, required: true }, // User's wallet or Payment wallet? Request implies "wallet address where payment should be sent" displayed, but usually we record "Tx Hash" or similar? Prompt says: "The crypto wallet address where bot purchase payments should be sent." -> This is static info. "After user submits... generate record... Fields: ... walletAddress". This likely means the wallet they sent TO, or FROM? "Manual confirmation" usually implies verifying a transaction from a user. Let's assume it stores the Wallet Address displayed to the user for reference, or the user's wallet if they input it. Given "Manual Confirmation", usually the User provides a TX ID or we just wait. The prompt says "Fields: ... walletAddress". I'll assume this is the Payment Wallet Address (System's) to track which wallet was used, IDK. Or maybe the user's wallet address for refund? Let's stick to the prompt list.
    // Actually, prompt says: "walletAddress". I will add it.
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending'
    },
    timestamp: { type: Date, default: Date.now },
    // Optional: Add admin comments or rejection reason later
});

const BotPurchase = mongoose.models.BotPurchase || mongoose.model('BotPurchase', botPurchaseSchema);
module.exports = BotPurchase;
