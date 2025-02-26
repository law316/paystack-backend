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
    const serviceAccount = require("./path-to-serviceAccountKey.json");

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: process.env.FIREBASE_DB_URL || "https://uyomeet-default-rtdb.firebaseio.com/",
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
app.set("trust proxy", 1); // Required for Render

app.use("/webhook", express.raw({ type: "application/json" }));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
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
    const secretKey = process.env.PAYSTACK_SECRET_KEY;
    const signature = req.headers["x-paystack-signature"];
    const rawBody = req.body;

    if (!signature) {
      return res.status(403).send("Forbidden: Missing signature");
    }

    const expectedSignature = crypto
      .createHmac("sha512", secretKey)
      .update(rawBody)
      .digest("hex");

    if (signature !== expectedSignature) {
      return res.status(403).send("Forbidden: Invalid signature");
    }

    const event = JSON.parse(rawBody.toString("utf8"));
    console.log("✅ Webhook Event Received:", event);

    if (event.event === "charge.success") {
      const { reference, customer, paid_at } = event.data;
      const email = customer?.email;

      if (!email) {
        return res.status(400).send("Invalid webhook: Missing email.");
      }

      const subscriptionStartDate = paid_at ? new Date(paid_at) : new Date();
      const subscriptionEndDate = new Date(subscriptionStartDate);
      subscriptionEndDate.setMonth(subscriptionEndDate.getMonth() + 1);

      const formattedStartDate = subscriptionStartDate.toISOString().split("T")[0];
      const formattedEndDate = subscriptionEndDate.toISOString().split("T")[0];

      const userList = await admin.auth().listUsers();
      const user = userList.users.find((u) => u.email === email);

      if (!user) {
        return res.status(404).send("User not found.");
      }

      const userUID = user.uid;
      const userRef = admin.database().ref(`users/${userUID}`);
      await userRef.update({
        isFreeUser: false,
        premiumMonths: 1,
        subscription: "Premium",
        subscriptionStartDate: formattedStartDate,
        subscriptionEndDate: formattedEndDate,
      });

      console.log(`✅ Subscription updated for ${email}: ${formattedStartDate} to ${formattedEndDate}`);
    }

    res.status(200).send("Webhook received");
  } catch (error) {
    console.error("🚨 Webhook Error:", error);
    res.status(500).send("Webhook processing failed");
  }
});

// ======================
// Start Server
// ======================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});