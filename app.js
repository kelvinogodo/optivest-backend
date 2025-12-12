const express = require('express')
const cors = require('cors')
const dotenv = require('dotenv')
const mongoose = require('mongoose')
const User = require('./models/user.model')
const Admin = require('./models/admin')
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Wallet = require('./models/wallet')
const nodemailer = require('nodemailer');
const BotPurchase = require('./models/botPurchase.model');
dotenv.config()

const app = express()

const jwtSecret = process.env.JWT_SECRET;


app.use(cors())
app.use(express.json())

const ATLAS_URI = process.env.ATLAS_URI;

if (!ATLAS_URI) {
  throw new Error("Please define the ATLAS_URI environment variable in Vercel");
}

/* Global cache so we don’t reconnect every time */
let cached = global.mongoose;
if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

const connectDB = async () => {
  if (cached.conn) return cached.conn;

  if (!cached.promise) {
    cached.promise = mongoose.connect(ATLAS_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }).then((mongoose) => mongoose);
  }

  cached.conn = await cached.promise;
  return cached.conn;
}
connectDB()

app.post('/api/verify', async (req, res) => {
  const {
    id
  } = req.body
  const user = await User.findOne({ _id: id })

  console.log(user)
  try {
    if (user.tradebotstatus) {
      await User.updateOne({ _id: id }, {
        tradebotstatus: false
      })
      res.json({
        status: 200, tradebotstatus: user
      })
    }
    else {
      await User.updateOne({ _id: id }, {
        tradebotstatus: true
      })
      res.json({
        status: 201, tradebotstatus: user
      })
    }
  } catch (error) {
    res.json({ status: 400, message: `error ${error}` })
  }
})


// register route 
app.post(
  '/api/register',
  async (req, res) => {
    const { firstName, lastName, userName, password, email, referralLink, country, phone } = req.body;
    const now = new Date();

    try {
      // Check if the user already exists
      const existingUser = await User.findOne({ email: email });
      if (existingUser) {
        return res.status(409).json({ status: 'error', message: 'Email or username already exists' });
      }

      // Check for referring user
      const referringUser = await User.findOne({ username: referralLink });
      if (referringUser) {

        // Update referring user's referral info

        await User.updateOne(
          { username: referralLink },
          {
            $push: {
              referred: {
                firstname: firstName,
                lastname: lastName,
                email: email,
                date: now.toLocaleString(),
                refBonus: 15,
              },
            },
            refBonus: referringUser.refBonus + 15,
            totalProfit: referringUser.totalProfit + 15,
            funded: referringUser.funded + 15,
            capital: referringUser.capital + 15
          }
        );
      }

      // Create a new user
      const newUser = await User.create({
        firstname: firstName,
        lastname: lastName,
        username: userName,
        phonenumber: phone,
        country: country,
        email,
        password: password,
        funded: 0,
        investment: [],
        transaction: [],
        withdraw: [],
        rememberme: false,
        referral: crypto.randomBytes(32).toString('hex'),
        refBonus: 0,
        referred: [],
        periodicProfit: 0,
        investCount: 0,
        upline: referralLink || null,
      });

      // Generate JWT token
      const token = jwt.sign(
        { id: newUser._id, email: newUser.email },
        process.env.JWT_SECRET || 'secret1258', // Use environment variable for security
        { expiresIn: '1h' }
      );

      // Prepare response data
      const response = {
        status: 'ok',
        email: newUser.email,
        name: newUser.firstname,
        token,
        adminSubject: 'User Signup Alert',
        message: `A new user with the following details just signed up:\nName: ${firstName} ${lastName}\nEmail: ${email}`,
        subject: 'Successful User Referral Alert',
      };

      if (referringUser) {
        response.referringUserEmail = referringUser.email;
        response.referringUserName = referringUser.firstname;
        response.referringUserMessage = `A new user with the name ${firstName} ${lastName} just signed up with your referral link. You will now earn 10% of every deposit this user makes. Keep referring to earn more.`;
      } else {
        response.referringUser = null;
      }

      return res.status(201).json(response);
    } catch (error) {
      console.error('Error during user registration:', error);
      return res.status(500).json({ status: 'error', message: 'Server error. Please try again later.' });
    }
  }
);

app.get('/:id/refer', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.id })
    if (!user) {
      return res.json({ status: 400 })
    }
    res.json({ status: 200, referredUser: req.params.id })
  } catch (error) {
    console.log(error)
    res.json({ status: `internal server error ${error}` })
  }
})


app.get('/api/getData', async (req, res) => {
  const token = req.headers['x-access-token'];
  try {
    // Ensure token is provided
    if (!token) {
      return res.status(401).json({ status: 'error', message: 'No token provided' });
    }

    // Verify token and decode user details
    const decoded = jwt.verify(token, jwtSecret); // Replace 'secret1258' with an environment variable for better security
    const email = decoded.email;

    // Fetch user data
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User not found' });
    }

    // Respond with user details
    res.status(200).json({
      status: 'ok',
      firstname: user.firstname,
      lastname: user.lastname,
      username: user.username,
      email: user.email,
      funded: user.funded,
      invest: user.investment,
      proofs: user.proofs,
      transaction: user.transaction,
      withdraw: user.withdraw,
      refBonus: user.refBonus,
      referred: user.referred,
      referral: user.referral,
      phonenumber: user.phonenumber,
      state: user.state,
      zipcode: user.zipcode,
      address: user.address,
      profilepicture: user.profilepicture,
      country: user.country,
      totalprofit: user.totalprofit,
      totaldeposit: user.totaldeposit,
      totalwithdraw: user.totalwithdraw,
      deposit: user.deposit,
      promo: user.promo,
      periodicProfit: user.periodicProfit,
      tradebotstatus: user.tradebotstatus,
      investCount: user.investCount,
      capital: user.capital
    });
  } catch (error) {
    console.error('Error fetching user data:', error.message);

    // Differentiate between invalid token and server error
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ status: 'error', message: 'Invalid token' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ status: 'error', message: 'Token expired' });
    }

    // Handle other server errors
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});



app.post('/api/updateUserData', async (req, res) => {
  const token = req.headers['x-access-token'];

  try {
    const decode = jwt.verify(token, jwtSecret);
    const email = decode.email;
    const user = await User.findOne({ email: email });

    if (!user) {
      return res.json({ status: 400, message: "User not found" });
    }

    // Prepare an object to hold only changed fields
    let updatedFields = {};

    // Loop through request body and compare with existing user data
    Object.keys(req.body).forEach((key) => {
      if (req.body[key] !== undefined && req.body[key] !== user[key]) {
        updatedFields[key] = req.body[key];
      }
    });

    // Ensure email remains unchanged
    delete updatedFields.email;

    // Update only if there are changes
    if (Object.keys(updatedFields).length > 0) {
      await User.updateOne({ email: user.email }, { $set: updatedFields });
      return res.json({ status: 200, message: "Profile updated successfully" });
    }

    return res.json({ status: 400, message: "No changes were made" });

  } catch (error) {
    console.error(error);
    return res.json({ status: 500, message: "Internal server error" });
  }
});




app.post('/api/fundwallet', async (req, res) => {
  try {
    const email = req.body.email
    const transactionId = req.body.transactionId
    const incomingAmount = req.body.amount
    const user = await User.findOne({ email: email })
    await User.updateOne(
      { email: email }, {
      $set: {
        funded: incomingAmount + user.funded,
        capital: user.capital + incomingAmount,
        totaldeposit: user.totaldeposit + incomingAmount,
        investCount: 0
      }
    }
    )
    const upline = await User.findOne({ username: user.upline })
    if (upline) {
      await User.updateOne({ username: user.upline }, {
        $set: {
          refBonus: 10 / 100 * incomingAmount,
          totalprofit: upline.totalprofit + (10 / 100 * incomingAmount),
          capital: upline.capital + (10 / 100 * incomingAmount),
          funded: upline.funded + (10 / 100 * incomingAmount),
        }
      })
    }

    await User.updateOne(
      { email: email },
      {
        $push: {
          deposit: {
            date: new Date().toLocaleString(),
            amount: incomingAmount,
            id: crypto.randomBytes(32).toString("hex"),
            balance: incomingAmount + user.funded
          }
        }, transaction: {
          type: 'Deposit',
          amount: incomingAmount,
          date: new Date().toLocaleString(),
          balance: incomingAmount + user.funded,
          id: crypto.randomBytes(32).toString("hex"),
        },
        proofs: req.body.proof
      }
    )

    if (upline) {
      res.json({
        status: 'ok',
        funded: req.body.amount,
        name: user.firstname,
        email: user.email,
        message: `your account has been credited with $${incomingAmount} USD. you can proceed to choosing your preferred investment plan to start earning. Thanks.`,
        subject: 'Deposit Successful',
        uplineName: upline.firstname,
        uplineEmail: upline.email,
        uplineSubject: `Earned Referral Commission`,
        uplineMessage: `Congratulations! You just earned $${10 / 100 * incomingAmount} in commission from ${user.firstname} ${user.lastname}'s deposit of $${incomingAmount}.`
      })
    }
    else {
      res.json({
        status: 'ok',
        funded: req.body.amount,
        name: user.firstname,
        email: user.email,
        message: `your account has been credited with $${incomingAmount} USD. you can proceed to choosing your preferred investment plan to start earning. Thanks.`,
        subject: 'Deposit Successful',
        upline: null
      })
    }

  } catch (error) {
    console.log(error)
    res.json({ status: 'error' })
  }
})

app.post('/api/admin', async (req, res) => {
  const admin = await Admin.findOne({ email: req.body.email })
  if (admin) {
    return res.json({ status: 200 })
  }
  else {
    return res.json({ status: 400 })
  }
})


app.post('/api/deleteUser', async (req, res) => {
  try {
    await User.deleteOne({ email: req.body.email })
    return res.json({ status: 200 })
  } catch (error) {
    return res.json({ status: 500, msg: `${error}` })
  }
})

app.post('/api/upgradeUser', async (req, res) => {
  try {
    const email = req.body.email
    const incomingAmount = req.body.amount
    const user = await User.findOne({ email: email })
    if (user) {
      await User.updateOne(
        { email: email }, {
        $set: {
          funded: incomingAmount + user.funded,
          capital: user.capital + incomingAmount,
          totalprofit: user.totalprofit + incomingAmount,
          periodicProfit: user.periodicProfit + incomingAmount
        }
      }
      )
      res.json({
        status: 'ok',
        funded: req.body.amount
      })
    }
  }
  catch (error) {
    res.json({
      status: 'error',
    })
  }


})

app.post('/api/withdraw', async (req, res) => {
  const token = req.headers['x-access-token']
  try {
    const decode = jwt.verify(token, jwtSecret)
    const email = decode.email
    const user = await User.findOne({ email: email })

    if (user.tradebotstatus) {
      if (user.capital >= req.body.WithdrawAmount) {
        await User.updateOne(
          { email: email },
          { $set: { funded: user.funded - req.body.WithdrawAmount, totalwithdraw: user.totalwithdraw + req.body.WithdrawAmount, capital: user.capital - req.body.WithdrawAmount } }
        )
        await User.updateOne(
          { email: email },
          {
            $push: {
              withdraw: {
                date: new Date().toLocaleString(),
                amount: req.body.WithdrawAmount,
                id: crypto.randomBytes(32).toString("hex"),
                balance: user.funded - req.body.WithdrawAmount
              }
            }
          }
        )
        const now = new Date()
        await User.updateOne(
          { email: email },
          {
            $push: {
              transaction: {
                type: 'withdraw',
                amount: req.body.WithdrawAmount,
                date: now.toLocaleString(),
                balance: user.funded - req.body.WithdrawAmount,
                id: crypto.randomBytes(32).toString("hex"),
              }
            }
          }
        )
        return res.json({
          status: 'ok',
          withdraw: req.body.WithdrawAmount,
          email: user.email,
          name: user.firstname,
          message: `We have received your withdrawal order, kindly exercise some patience as our management board approves your withdrawal`,
          subject: 'Withdrawal Order Alert',
          adminMessage: `Hello BOSS! a user with the name ${user.firstname} placed withdrawal of $${req.body.WithdrawAmount} USD, to be withdrawn into ${req.body.wallet} ${req.body.method} wallet`,
        })
      }

    }
    else if (user.totalprofit >= req.body.WithdrawAmount) {
      await User.updateOne(
        { email: email },
        { $set: { funded: user.funded - req.body.WithdrawAmount, totalwithdraw: user.totalwithdraw + req.body.WithdrawAmount, capital: user.capital - req.body.WithdrawAmount } }
      )
      await User.updateOne(
        { email: email },
        {
          $push: {
            withdraw: {
              date: new Date().toLocaleString(),
              amount: req.body.WithdrawAmount,
              id: crypto.randomBytes(32).toString("hex"),
              balance: user.funded - req.body.WithdrawAmount
            }
          }
        }
      )
      const now = new Date()
      await User.updateOne(
        { email: email },
        {
          $push: {
            transaction: {
              type: 'withdraw',
              amount: req.body.WithdrawAmount,
              date: now.toLocaleString(),
              balance: user.funded - req.body.WithdrawAmount,
              id: crypto.randomBytes(32).toString("hex"),
            }
          }
        }
      )
      return res.json({
        status: 'ok',
        withdraw: req.body.WithdrawAmount,
        email: user.email,
        name: user.firstname,
        message: `We have received your withdrawal order, kindly exercise some patience as our management board approves your withdrawal`,
        subject: 'Withdrawal Order Alert',
        adminMessage: `Hello BOSS! a user with the name ${user.firstname} placed withdrawal of $${req.body.WithdrawAmount} USD, to be withdrawn into ${req.body.wallet} ${req.body.method} wallet`,
      })
    }

    else {
      res.json({
        status: 400,
        subject: 'Failed Withdrawal Alert',
        email: user.email,
        name: user.firstname,
        withdrawMessage: `We have received your withdrawal order, but you can only withdraw your profit. To withdraw capital and profit, you will have to purchase a third-party trading bot in the trading bot page, Thanks.`
      })
    }
  }
  catch (error) {
    console.log(error)
    res.json({ status: 'error', message: 'internal server error' })
  }
})

app.post('/api/sendproof', async (req, res) => {
  const token = req.headers['x-access-token']
  const { transactionId } = req.body
  try {
    const decode = jwt.verify(token, jwtSecret)
    const email = decode.email
    const user = await User.findOne({ email: email })
    if (user) {
      return res.json({
        status: 200,
        email: user.email,
        name: user.firstname,
        message: `Hi! you have successfully placed a deposit order, kindly exercise some patience as we verify your deposit. Your account will automatically be credited with $${req.body.amount} USD after verification.`,
        subject: 'Pending Deposit Alert',
        adminMessage: `hello BOSS, a user with the name.${user.firstname}, just deposited $${req.body.amount} USD into to your ${req.body.method} wallet.The transaction id is ${transactionId}.  please confirm deposit and credit.`,
        adminSubject: 'Deposit Alert'
      })
    }
    else {
      return res.json({ status: 500 })
    }
  } catch (error) {
    console.log(error)
    res.json({ status: 404 })
  }
})



const SECRET_KEY = process.env.JWT_SECRET || 'defaultsecretkey'; // Replace with your actual secret stored in .env

app.post('/api/login', async (req, res) => {
  try {
    const { email, password, rememberme } = req.body;

    // Check if the user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ status: 404, message: 'User does not exist' });
    }

    // Verify password
    // const isPasswordValid = await bcrypt.compare(password, user.password);
    if (password != user.password) {
      return res.json({ status: 401, message: 'Incorrect password' });
    }

    if (user.isActive === false) {
      return res.json({ status: 403, message: 'Your account is currently deactivated.' });
    }

    if (user.isActive === false) {
      return res.json({ status: 403, message: 'Your account is currently deactivated.' });
    }

    // Generate JWT token with user ID and email
    const token = jwt.sign(
      { id: user._id, email: user.email },
      SECRET_KEY,
      { expiresIn: '7d' } // Set token to expire in 7 days
    );

    // Update the user's "remember me" status
    user.rememberme = rememberme || false;
    await user.save();

    // Send response
    return res.status(200).json({
      status: 'ok',
      token,
      message: 'Login successful',
    });
  } catch (error) {
    console.error('Error during login:', error);
    return res.json({ status: 'error', message: 'Internal server error' });
  }
});


app.get('/api/getUsers', async (req, res) => {
  const users = await User.find()
  res.json(users)
})


// ==========================================
// 1. CONFIGURATION (Source of Truth)
// ==========================================
// Define plans here to avoid hardcoded values in logic and ensure security.
const PLAN_CONFIG = {
  'Tryo Plan': {
    weeklyPercent: 7.5,
    durationDays: 365
  },
  'Ruby Account': {
    weeklyPercent: 20.0,
    durationDays: 365
  },
  'Medial Plan': {
    weeklyPercent: 25.90,
    durationDays: 365
  },
  'Veltrix Plan': {
    weeklyPercent: 39.90,
    durationDays: 365
  },
  'VIP I': {
    weeklyPercent: 41.30,
    durationDays: 7
  },
  'VIP II': {
    weeklyPercent: 45.96,
    durationDays: 7
  }
};

// Helper: safe float math (optional but good practice for money)
const calculateProfit = (amount, percent) => {
  return (amount * percent) / 100;
};


// ==========================================
// 2. INVESTMENT ROUTE
// ==========================================
app.post('/api/invest', async (req, res) => {
  const token = req.headers['x-access-token'];

  try {
    const decode = jwt.verify(token, jwtSecret);
    const email = decode.email;
    const user = await User.findOne({ email: email });

    if (!user) {
      return res.json({ status: 404, message: 'User not found' });
    }

    if (user.investCount >= 3) { // Changed == 3 to >= 3 for safety
      return res.json({ status: 403, error: 'Re-investment limit reached. Deposit to keep investing.' });
    }

    const { amount, plan: planName } = req.body;

    // VALIDATION: Check if plan exists in our config
    const planConfig = PLAN_CONFIG[planName];
    if (!planConfig) {
      return res.json({ status: 400, message: 'Invalid investment plan selected.' });
    }

    // Capital Check
    if (user.capital < amount) {
      return res.json({ status: 400, message: 'Insufficient capital!' });
    }

    // CALCULATION ---------------------------
    // Use server-side config for calculations, NOT client input
    const periodicProfit = calculateProfit(amount, planConfig.weeklyPercent);

    // Calculate total expected profit over the full duration? 
    // If the plan pays weekly for X days:
    // Number of payouts = Duration Days / 7
    // Total Profit = periodicProfit * (Duration Days / 7)
    // Note: If you want exactly 52 weeks or a specific number of payouts, logic might need adjustment.
    // For now, we store the periodic (weekly) profit amount to be paid out by the Cron job.

    const now = new Date();
    const durationMs = planConfig.durationDays * 24 * 60 * 60 * 1000;
    const endDate = new Date(now.getTime() + durationMs);

    // DATABASE UPDATE -----------------------
    await User.updateOne(
      { email: email },
      {
        $push: {
          investment: {
            type: 'investment',
            amount: amount,
            plan: planName,
            percent: `${planConfig.weeklyPercent}%`, // Store formatted string for display
            startDate: now.toLocaleString(),
            endDate: endDate.toLocaleString(),
            endDateMs: endDate.getTime(), // Store raw MS for easier comparison in Cron
            profit: periodicProfit, // This is the WEEKLY profit amount
            periodicProfit: periodicProfit,
            started: now.getTime(),
            nextPayout: now.getTime() + (7 * 24 * 60 * 60 * 1000), // First payout in 7 days
            totalEarned: 0,
            active: true
          },
          transaction: {
            type: 'investment',
            amount: amount,
            date: now.toLocaleString(),
            balance: user.funded + amount, // Note: Logic check - is balance increasing or decreasing? Usually investing subtracts capital?
            // Existing logic had: balance: user.funded + req.body.amount. Keeping consistent with user's logic but double check.
            id: crypto.randomBytes(32).toString("hex")
          }
        },
        $set: {
          capital: user.capital - amount,
          // totalprofit: user.totalprofit + money // removing immediate profit addition, profit is earned over time
          withdrawDuration: now.getTime(),
          investCount: user.investCount + 1
        },
      }
    );

    res.json({ status: 'ok', amount: amount });

  } catch (error) {
    console.error("Investment Error:", error);
    return res.json({ status: 500, error: 'Internal server error' });
  }
});


// ==========================================
// 3. CRON JOB (Profit Distribution)
// ==========================================
// Updates user balances with profit if the week has passed
const processInvestments = async (users, now) => {
  const updates = [];

  for (const user of users) {
    if (!user.investment || user.investment.length === 0) continue;

    let userChanged = false;
    let newFunded = user.funded || 0;
    let newTotalProfit = user.totalprofit || 0;
    let newCapital = user.capital || 0; // Existing logic seemed to add profit to capital too?

    // Map through investments to check updates
    // We use a regular for-loop to support async/await if needed, or just standard mapping
    const updatedInvestments = user.investment.map(invest => {
      // Skip invalid records
      if (!invest.started || !invest.nextPayout) return invest;
      if (!invest.active && invest.active !== undefined) return invest; // If we track active status

      // Check if investment has ended
      // Using endDateMs if we stored it, or calculating from duration
      const endTime = invest.endDateMs || (invest.started + (invest.ended || 0)); // Fallback to old logic if needed

      if (now >= endTime) {
        // Investment expired
        invest.active = false;
        return invest;
      }

      // Check if it's time for a payout
      if (now >= invest.nextPayout) {
        const profitAmount = invest.periodicProfit || invest.profit; // Support both naming conventions

        if (profitAmount && !isNaN(profitAmount)) {
          // PAYOUT!
          newFunded += profitAmount;
          newTotalProfit += profitAmount;
          newCapital += profitAmount; // Based on your old logic: capital: user.capital + invest.profit

          invest.totalEarned = (invest.totalEarned || 0) + profitAmount;

          // Schedule next payout (add 7 days)
          invest.nextPayout += (7 * 24 * 60 * 60 * 1000);

          // If we missed multiple weeks (server down), this loop only pays once. 
          // To pay multiple weeks at once, you'd use a while loop here, but safer to do one at a time.

          userChanged = true;
        }
      }
      return invest;
    });

    if (userChanged) {
      updates.push(
        User.updateOne(
          { email: user.email },
          {
            $set: {
              funded: newFunded,
              totalprofit: newTotalProfit,
              capital: newCapital,
              investment: updatedInvestments
            }
          }
        )
      );
    }
  }

  // Execute all DB updates
  await Promise.all(updates);
  return updates.length;
};

app.get('/api/cron', async (req, res) => {
  try {
    const users = await User.find();
    const now = new Date().getTime();

    const count = await processInvestments(users, now);

    // Send ONE response after all processing is done
    return res.json({ status: 200, message: `Processed updates for ${count} users.` });

  } catch (error) {
    console.log(error);
    return res.json({ status: 500, message: 'Error executing cron job' });
  }
});


app.post('/api/getWithdrawInfo', async (req, res) => {
  try {
    const user = await User.findOne({
      email: req.body.email,
    })
    if (user) {
      const userAmount = user.withdraw[user.withdraw.length - 1].amount
      return res.json({ status: 'ok', amount: userAmount })
    }
  }
  catch (err) {
    return res.json({ status: 'error', user: false })
  }
})

app.post('/api/updateWallet', async (req, res) => {
  const { address, type, network } = req.body
  try {
    const wallet = await Wallet.findOne({
      type: type,
    })
    if (wallet) {
      await Wallet.updateOne({ type: type }, {
        address: address, type: type, network: network
      })
      return res.json({ status: 'ok', message: 'wallet updated' })
    }
  }
  catch (err) {
    return res.json({ status: 'error', user: false })
  }
})

app.post('/api/updateAdminPassword', async (req, res) => {
  const newPassword = req.body.newPassword
  try {

    await Admin.updateOne({ email: 'boardbank.com@gmail.com' }, {
      password: newPassword
    })
    return res.json({ status: 'ok', message: 'password updated' })
  }
  catch (err) {
    return res.json({ status: 'error', error: err })
  }
})

app.get('/api/fetchWallets', async (req, res) => {
  try {
    const wallets = await Wallet.find()
    return res.json({ status: 200, wallets: wallets })
  } catch (error) {
    console.log(error)
    return res.json({ status: 500, message: 'sorry, no wallets found' })
  }
})

// ==========================================
// CONFIGURATION: Nodemailer Transporter
// ==========================================
// Replace with your actual SMTP credentials or service (e.g., Gmail, SendGrid, etc.)
const transporter = nodemailer.createTransport({
  service: 'gmail', // or 'smtp.example.com'
  auth: {
    user: 'boardbank.com@gmail.com', // Your email
    pass: 'pbpzdkomeiwviset'     // Your app password (not login password)
  }
});

// ==========================================
// ROUTE: Send Bulk Email
// ==========================================
app.post('/api/admin/send-bulk-email', async (req, res) => {
  // 1. Security: Verify Admin (Optional but recommended)
  // const token = req.headers['x-access-token'];
  // ... verify token logic ...

  const { subject, message } = req.body;

  if (!subject || !message) {
    return res.json({ status: 400, message: 'Subject and message are required.' });
  }

  try {
    // 2. Fetch All Users
    const users = await User.find({}, 'email firstname lastname'); // Select only needed fields

    if (!users || users.length === 0) {
      return res.json({ status: 404, message: 'No users found to email.' });
    }

    let sentCount = 0;
    let failedCount = 0;

    // 3. Send Emails Loop
    // We use Promise.all to send in parallel (be careful with rate limits!)
    // Or specific batching if user base is huge. For now, simple loop.

    const emailPromises = users.map(user => {
      const mailOptions = {
        from: '"BoardBank Support" <support@boardbanking.com>',
        to: user.email,
        subject: subject,
        // Simple HTML template
        html: `
                    <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
                        <h2>Hello ${user.firstname || 'Valued User'},</h2>
                        <p>${message.replace(/\n/g, '<br>')}</p>
                        <hr>
                        <p style="font-size: 12px; color: #777;">&copy; ${new Date().getFullYear()} BoardBank. All rights reserved.</p>
                    </div>
                `
      };

      return transporter.sendMail(mailOptions)
        .then(() => {
          sentCount++;
        })
        .catch(err => {
          console.error(`Failed to email ${user.email}:`, err);
          failedCount++;
        });
    });

    await Promise.all(emailPromises);

    // 4. Response
    return res.json({
      status: 'ok',
      message: `Emails processed. Sent: ${sentCount}, Failed: ${failedCount}`,
      sent: sentCount,
      failed: failedCount
    });

  } catch (error) {
    console.error('Bulk Email Error:', error);
    return res.json({ status: 500, error: 'Internal server error during bulk email.' });
  }
});

app.post('/api/admin/users/:id/toggle-status', async (req, res) => {
  const { id } = req.params;
  try {
    const user = await User.findById(id);
    if (!user) {
      return res.json({ status: 404, message: 'User not found' });
    }
    user.isActive = !user.isActive;
    await user.save();
    res.json({ status: 200, message: `User ${user.isActive ? 'activated' : 'deactivated'} successfully`, isActive: user.isActive });
  } catch (error) {
    console.error(error);
    res.json({ status: 500, message: 'Error toggling user status' });
  }
});


// ==========================================
// BOT PURCHASE ROUTES
// ==========================================

// 1. User submits a bot purchase request
app.post('/api/bot-purchase', async (req, res) => {
  const { userId, botId, amount, walletAddress } = req.body;
  try {
    const newPurchase = await BotPurchase.create({
      userId,
      botId,
      amount,
      walletAddress,
      status: 'pending'
    });

    const user = await User.findById(userId);

    // Email to User
    // Use global transporter
    const userMailOptions = {
      from: '"BoardBank Support" <boardbank.com@gmail.com>',
      to: user.email,
      subject: 'Bot Purchase Request Received',
      html: `<h3>Hello ${user.firstname},</h3><p>We have received your payment request for <b>${botId}</b>.</p><p>Our admin team will confirm the payment manually. You will receive an email once approved.</p>`
    };
    transporter.sendMail(userMailOptions, (err, info) => {
      if (err) console.log('Email error:', err);
    });

    res.json({ status: 'ok', message: 'Purchase request submitted successfully' });
  } catch (error) {
    console.error(error);
    res.json({ status: 500, message: 'Internal server error' });
  }
});

// 2. Admin views all bot purchase requests
app.get('/api/admin/bot-purchases', async (req, res) => {
  try {
    const requests = await BotPurchase.find().sort({ timestamp: -1 });
    // Enrich with user details
    const enrichedRequests = await Promise.all(requests.map(async (req) => {
      const user = await User.findById(req.userId);
      return {
        ...req._doc,
        username: user ? user.username : 'Unknown',
        email: user ? user.email : 'Unknown'
      };
    }));
    res.json({ status: 'ok', requests: enrichedRequests });
  } catch (error) {
    res.json({ status: 500, message: 'internal error' });
  }
});

// 3. Admin approves or rejects
app.post('/api/admin/bot-purchases/:id/decision', async (req, res) => {
  const { id } = req.params;
  const { decision } = req.body; // 'approved' or 'rejected'

  try {
    const purchase = await BotPurchase.findById(id);
    if (!purchase) return res.json({ status: 404, message: 'Request not found' });

    if (purchase.status !== 'pending') {
      return res.json({ status: 400, message: 'Request already processed' });
    }

    const user = await User.findById(purchase.userId);


    if (decision === 'approved') {
      purchase.status = 'approved';
      await purchase.save();

      user.tradebotstatus = true;

      // Deduct amount from user funds as requested
      // We assume user has funds or we allow negative (or user logic handles it)
      // Per request: "subtracted from the user's funded and capital"
      user.funded = (user.funded || 0) - purchase.amount;
      user.capital = (user.capital || 0) - purchase.amount;

      await user.save();

      const mailOptions = {
        from: '"BoardBank Support" <boardbank.com@gmail.com>',
        to: user.email,
        subject: 'Bot Purchase Approved!',
        html: `<h3>Congratulations ${user.firstname}!</h3><p>Your purchase of <b>${purchase.botId}</b> has been approved.</p><p>You can now access trading bot features.</p>`
      };
      transporter.sendMail(mailOptions);

    } else if (decision === 'rejected') {
      purchase.status = 'rejected';
      await purchase.save();

      const mailOptions = {
        from: '"BoardBank Support" <boardbank.com@gmail.com>',
        to: user.email,
        subject: 'Bot Purchase Rejected',
        html: `<h3>Hello ${user.firstname},</h3><p>We regret to inform you that your purchase request for <b>${purchase.botId}</b> was rejected.</p><p>Please contact support if you believe this is a mistake.</p>`
      };
      transporter.sendMail(mailOptions);
    }

    res.json({ status: 'ok', message: `Request ${decision}` });

  } catch (error) {
    console.error(error);
    res.json({ status: 500, message: 'Internal error' });
  }
});

module.exports = app

