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
app.use(express.json()); // ✅ General route parsing

// ✅ Rate limiter to prevent abuse
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(apiLimiter);

// ✅ Webhook route must parse raw body separately
app.use("/webhook", express.raw({ type: "application/json" }));

// ======================
// Helper Functions
// ======================
const validateWebhook = (receivedHash, rawBody) => {
  const expectedHash = crypto
    .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
    .update(rawBody) // Use raw body directly (Buffer)
    .digest("hex");
  return receivedHash === expectedHash;
};

const sanitizeEmail = (email) => (email ? email.toLowerCase().trim() : null);

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

// 📌 Webhook for Automatic Updates
app.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const signature = req.headers["x-paystack-signature"]; // Get the signature from headers
    const rawBody = req.body; // `express.raw()` provides the raw body as a Buffer

    if (!signature) {
      console.warn("❌ Missing webhook signature");
      return res.sendStatus(403); // Forbidden
    }

    // Compute the expected signature
    const expectedSignature = crypto
      .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
      .update(rawBody) // Use raw body directly
      .digest("hex");

    console.log("Received Signature:", signature);
    console.log("Computed Signature:", expectedSignature);

    // Verify the signature
    if (signature !== expectedSignature) {
      console.warn("❌ Invalid webhook signature");
      return res.sendStatus(403); // Forbidden
    }

    // Parse the raw body into JSON
    const event = JSON.parse(rawBody.toString("utf8")); // Convert Buffer to string, then parse JSON

    console.log("🔔 Webhook Event Received:", event);

    // Handle the event (e.g., charge.success)
    if (event.event === "charge.success") {
      const { reference, customer } = event.data;
      console.log(`🔄 Processing payment ${reference} for ${customer.email}`);

      // Verify the transaction with Paystack
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

    // Acknowledge receipt of the event
    res.sendStatus(200); // Always respond with 200 OK to prevent retries
  } catch (error) {
    console.error("🚨 Webhook Error:", error);
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