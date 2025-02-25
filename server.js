const express = require("express");
const cors = require("cors");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto"); // Import only once at the top
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
app.post("/webhook", (req, res) => {
  try {
    const secretKey = process.env.PAYSTACK_SECRET_KEY; // Paystack secret key
    const signature = req.headers["x-paystack-signature"]; // Signature from Paystack
    const rawBody = req.body; // Use the raw body captured by express.raw()

    if (!signature) {
      console.error("❌ Missing webhook signature");
      return res.status(403).send("Forbidden: Missing signature");
    }

    // Compute the expected signature using the raw body
    const expectedSignature = crypto
      .createHmac("sha512", secretKey)
      .update(rawBody) // Use raw body directly
      .digest("hex");

    // Compare the signatures
    if (signature !== expectedSignature) {
      console.error("❌ Invalid webhook signature");
      console.log("Expected Signature:", expectedSignature);
      console.log("Received Signature:", signature);

      // Reject the request if signatures don't match
      return res.status(403).send("Forbidden: Invalid signature");
    }

    // Parse the raw body into JSON AFTER validating the signature
    const event = JSON.parse(rawBody.toString("utf8"));

    // Log the received event
    console.log("✅ Webhook Event Received:", event);

    // Handle Paystack events (e.g., charge.success)
    if (event.event === "charge.success") {
      const { reference, customer } = event.data;

      // Example: Verify the transaction with Paystack
      console.log(`✅ Payment verified for ${customer.email} with reference ${reference}`);
    }

    // Respond with 200 to acknowledge receipt of the webhook
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