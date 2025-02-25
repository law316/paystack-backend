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

// ✅ Webhook must parse raw body separately BEFORE global JSON middleware
app.use("/webhook", express.raw({ type: "application/json" }));

// ✅ Other middleware (AFTER webhook)
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ Rate limiter to prevent abuse
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(apiLimiter);

// ======================
// Webhook Route
// ======================
app.post("/webhook", async (req, res) => {
  try {
    const secret = process.env.PAYSTACK_SECRET_KEY; // Use your Paystack secret key
    const signature = req.headers["x-paystack-signature"]; // Get the signature from headers
    const rawBody = req.body; // Use raw body captured by express.raw()

    if (!signature) {
      console.warn("❌ Missing webhook signature");
      return res.status(403).send("Forbidden: Missing signature");
    }

    // Compute the expected signature
    const expectedSignature = crypto
      .createHmac("sha512", secret)
      .update(rawBody)
      .digest("hex");

    if (signature !== expectedSignature) {
      console.error("❌ Invalid webhook signature");
      console.log("Expected Signature:", expectedSignature);
      console.log("Received Signature:", signature);
      return res.status(403).send("Forbidden: Invalid signature");
    }

    // Parse raw body into JSON after signature validation
    const event = JSON.parse(rawBody.toString("utf8"));

    console.log("✅ Webhook Event Received:", event);

    if (event.event === "charge.success") {
      const { reference, customer } = event.data;

      // Verify the transaction with Paystack
      const verification = await axios.get(
        `https://api.paystack.co/transaction/verify/${reference}`,
        {
          headers: { Authorization: `Bearer ${secret}` },
        }
      );

      if (verification.data.data.status === "success") {
        console.log(`✅ Payment verified for ${customer.email}`);
        // Your logic for handling successful payments
        await updateUserSubscription(reference, customer.email);
      }
    }

    res.status(200).send("Webhook received");
  } catch (error) {
    console.error("🚨 Webhook Error:", error);
    res.status(500).send("Webhook processing failed");
  }
});

// ======================
// Create Access Code Route
// ======================
app.post("/create-access-code", async (req, res) => {
  try {
    const { email, amount } = req.body;

    if (!email || !amount) {
      return res.status(400).json({ status: false, message: "Email and amount are required." });
    }

    const paystackResponse = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      { email, amount },
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    const accessCode = paystackResponse.data.data.access_code;
    const authorizationUrl = paystackResponse.data.data.authorization_url;

    res.status(200).json({
      status: true,
      message: "Access code created successfully.",
      accessCode,
      authorizationUrl,
    });
  } catch (error) {
    console.error("🚨 Error creating access code:", error.response?.data || error.message);
    res.status(500).json({
      status: false,
      message: "Failed to create access code.",
      error: error.response?.data || error.message,
    });
  }
});

// ======================
// Start Server
// ======================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});