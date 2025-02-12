const express = require("express");
const cors = require("cors");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const admin = require("firebase-admin");
const bodyParser = require("body-parser"); // ✅ Ensure body-parser is used
require("dotenv").config();

// ======================
// Initialize Firebase
// ======================
if (!admin.apps.length) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DB_URL
  });
}

// ======================
// Initialize Express
// ======================
const app = express();

// ======================
// Middleware
// ======================
app.use(bodyParser.json()); // ✅ Ensure JSON parsing
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(apiLimiter);

// ✅ Webhook must parse raw body separately
app.use("/webhook", express.raw({ type: "application/json" }));

// ======================
// Helper Functions
// ======================
const validateWebhook = (receivedHash, payload) => {
  const expectedHash = crypto
    .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
    .update(payload)
    .digest("hex");
  return receivedHash === expectedHash;
};

const sanitizeEmail = (email) => {
  return email ? email.toLowerCase().trim() : null;
};

const updateUserSubscription = async (reference, email) => {
  try {
    const db = admin.database();
    const usersRef = db.ref("users");
    
    const snapshot = await usersRef.orderByChild("email").equalTo(email).once("value");
    const userData = snapshot.val();
    if (!userData) return false;

    const userId = Object.keys(userData)[0];
    
    const currentDate = new Date();
    const subscriptionEnd = new Date(currentDate.setMonth(currentDate.getMonth() + 1));
    
    await usersRef.child(userId).update({
      isPremium: true,
      subscriptionStart: new Date().toISOString(),
      subscriptionEnd: subscriptionEnd.toISOString(),
      lastPaymentReference: reference
    });
    
    console.log(`Updated subscription for ${email}`);
    return true;
  } catch (error) {
    console.error("Firebase update error:", error);
    return false;
  }
};

// ======================
// Routes
// ======================

// 📌 Create Payment Link
app.post("/create-access-code", async (req, res) => {
  try {
    const { email: rawEmail, amount } = req.body;
    const email = sanitizeEmail(rawEmail);

    if (!email || !amount || typeof amount !== "number" || amount <= 0) {
      return res.status(400).json({ status: false, message: "Valid email and positive amount required" });
    }

    const amountInKobo = amount * 100;

    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email,
        amount: amountInKobo,
        callback_url: `${process.env.BASE_URL}/verify-payment`
      },
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      }
    );

    res.status(200).json({
      status: true,
      data: {
        authorization_url: response.data.data.authorization_url,
        reference: response.data.data.reference
      }
    });

  } catch (error) {
    console.error("Payment error:", error.response?.data || error.message);
    res.status(500).json({ status: false, message: "Payment initialization failed" });
  }
});

// 📌 Verify Payment After Completion
app.post("/verify-transaction", async (req, res) => {
  try {
    const { reference, email } = req.body;

    if (!reference || !email) {
      return res.status(400).json({ status: false, message: "Reference and email required" });
    }

    console.log(`🔍 Verifying transaction: ${reference} for ${email}`);

    // ✅ Call Paystack's API to verify the transaction
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      }
    );

    console.log("🔍 Paystack Response Data:", response.data); // Debugging log

    // ✅ Ensure response contains the expected structure
    if (response.data && response.data.data && response.data.data.status === "success") {
      await updateUserSubscription(reference, email);

      return res.json({
        status: true,
        message: "Payment verified successfully",
        reference: reference,
        email: email,
      });
    }

    return res.status(400).json({
      status: false,
      message: "Payment not completed or failed",
      reference: reference,
      email: email,
    });

  } catch (error) {
    console.error("🚨 Verification error:", error.response?.data || error.message);

    return res.status(500).json({
      status: false,
      message: "Transaction verification failed",
      error: error.response?.data || error.message,
    });
  }
});

// 📌 Webhook for Automatic Updates
app.post("/webhook", async (req, res) => {
  try {
    const signature = req.headers["x-paystack-signature"];
    if (!signature || !validateWebhook(signature, req.body)) {
      console.warn("Invalid webhook signature");
      return res.sendStatus(403);
    }

    const event = JSON.parse(req.body.toString()); // ✅ Fix: Ensure JSON parsing
    
    if (event.event === "charge.success") {
      const { reference, customer } = event.data;
      console.log(`Processing payment ${reference} for ${customer.email}`);

      const verification = await axios.get(
        `https://api.paystack.co/transaction/verify/${reference}`,
        {
          headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
        }
      );

      if (verification.data.data.status === "success") {
        await updateUserSubscription(reference, customer.email);
        console.log(`Completed processing for ${reference}`);
      }
    }

    res.sendStatus(200);
  } catch (error) {
    console.error("Webhook error:", error);
    res.status(500).json({ status: false, message: "Webhook processing failed" });
  }
});

// ======================
// Start Server
// ======================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});