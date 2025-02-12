const express = require("express");
const cors = require("cors");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const admin = require("firebase-admin");
require("dotenv").config();

// ======================
// Initialize Firebase
// ======================
if (!admin.apps.length) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: process.env.FIREBASE_DB_URL,
    });

    console.log("✅ Firebase initialized successfully.");
  } catch (error) {
    console.error("🚨 Firebase initialization failed:", error);
    process.exit(1);
  }
}

// ======================
// Initialize Express
// ======================
const app = express();
app.set("trust proxy", 1); // ✅ Required for Render

// ======================
// Middleware
// ======================
app.use(cors());
app.use(express.json()); // ✅ Use for general routes

// ✅ Rate limiter to prevent abuse
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
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

const sanitizeEmail = (email) => email ? email.toLowerCase().trim() : null;

const updateUserSubscription = async (reference, email) => {
  try {
    const db = admin.database();
    const usersRef = db.ref("users");

    const snapshot = await usersRef.orderByChild("email").equalTo(email).once("value");
    const userData = snapshot.val();
    if (!userData) return false;

    const userId = Object.keys(userData)[0];
    const subscriptionEnd = new Date();
    subscriptionEnd.setMonth(subscriptionEnd.getMonth() + 1);

    await usersRef.child(userId).update({
      isPremium: true,
      subscriptionStart: new Date().toISOString(),
      subscriptionEnd: subscriptionEnd.toISOString(),
      lastPaymentReference: reference,
    });

    console.log(`✅ Subscription updated for ${email}`);
    return true;
  } catch (error) {
    console.error("🚨 Firebase update error:", error);
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
        callback_url: `${process.env.BASE_URL}/verify-payment`,
      },
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      }
    );

    res.status(200).json({
      status: true,
      data: {
        authorization_url: response.data.data.authorization_url,
        reference: response.data.data.reference,
      },
    });

  } catch (error) {
    console.error("🚨 Payment error:", error.response?.data || error.message);
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

    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      }
    );

    console.log("🔍 Paystack Response Data:", response.data);

    if (response.data?.data?.status === "success") {
      await updateUserSubscription(reference, email);
      return res.json({
        status: true,
        message: "Payment verified successfully",
        reference,
        email,
      });
    }

    return res.status(400).json({
      status: false,
      message: "Payment not completed or failed",
      reference,
      email,
    });

  } catch (error) {
    console.error("🚨 Verification error:", error.response?.data || error.message);
    res.status(500).json({
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
    const rawBody = req.body.toString(); // ✅ Convert raw buffer to string

    if (!signature || !validateWebhook(signature, rawBody)) {
      console.warn("❌ Invalid webhook signature");
      return res.sendStatus(403);
    }

    const event = JSON.parse(rawBody);
    console.log("🔔 Webhook Event Received:", event);

    if (event.event === "charge.success") {
      const { reference, customer } = event.data;
      console.log(`🔄 Processing payment ${reference} for ${customer.email}`);

      const verification = await axios.get(
        `https://api.paystack.co/transaction/verify/${reference}`,
        {
          headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
        }
      );

      if (verification.data.data.status === "success") {
        await updateUserSubscription(reference, customer.email);
        console.log(`✅ Payment processed successfully for ${customer.email}`);
      }
    }

    res.sendStatus(200);
  } catch (error) {
    console.error("🚨 Webhook error:", error);
    res.status(500).json({ status: false, message: "Webhook processing failed" });
  }
});

// ======================
// Start Server
// ======================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});