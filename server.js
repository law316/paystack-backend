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
app.post("/webhook", async (req, res) => {
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
      return res.status(403).send("Forbidden: Invalid signature");
    }

    // Parse the raw body into JSON AFTER validating the signature
    const event = JSON.parse(rawBody.toString("utf8"));

    console.log("✅ Webhook Event Received:", event);

    if (event.event === "charge.success") {
      const { reference, customer, paid_at } = event.data;

      // Validate `paid_at` date
      if (!paid_at) {
        console.error("❌ Missing `paid_at` field in the webhook event.");
        return res.status(400).send("Invalid webhook event: Missing `paid_at` field.");
      }

      const subscriptionStartDate = new Date(paid_at);
      if (isNaN(subscriptionStartDate)) {
        console.error("❌ Invalid `paid_at` date format:", paid_at);
        return res.status(400).send("Invalid webhook event: Invalid `paid_at` value.");
      }

      const subscriptionEndDate = new Date(subscriptionStartDate);
      subscriptionEndDate.setMonth(subscriptionEndDate.getMonth() + 1); // Add 1 month

      // Format the dates as "yyyy-MM-dd"
      const formattedStartDate = subscriptionStartDate.toISOString().split("T")[0];
      const formattedEndDate = subscriptionEndDate.toISOString().split("T")[0];

      // Get the user's email
      const email = customer.email;

      // Find the user's UID in Firebase Authentication
      const userList = await admin.auth().listUsers();
      const user = userList.users.find((u) => u.email === email);

      if (!user) {
        console.error(`❌ User with email ${email} not found in Firebase Authentication.`);
        return res.status(404).send("User not found");
      }

      const userUID = user.uid; // Get the user's UID

      // Update the user's subscription details in the Realtime Database
      const userRef = admin.database().ref(`users/${userUID}`);
      await userRef.update({
        isFreeUser: false,
        premiumMonths: 1, // Increment number of months based on your logic
        subscription: "Premium",
        subscriptionStartDate: formattedStartDate,
        subscriptionEndDate: formattedEndDate,
      });

      console.log(`✅ Subscription updated for ${email}: ${formattedStartDate} to ${formattedEndDate}`);
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

    // Convert amount from Naira to Kobo
    const amountInKobo = amount * 100;

    const paystackResponse = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      { email, amount: amountInKobo }, // Send the converted amount in Kobo
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    // Extract the necessary fields from the Paystack response
    const accessCode = paystackResponse.data.data.access_code;
    const authorizationUrl = paystackResponse.data.data.authorization_url;

    // Respond with the correct structure, wrapping the fields inside a "data" object
    res.status(200).json({
      status: true,
      message: "Access code created successfully.",
      data: {
        accessCode: accessCode,
        authorizationUrl: authorizationUrl,
      },
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

// Example function to activate subscription
function activateSubscription(email, reference, data) {
  console.log(
    `Activating subscription for ${email} with payment reference: ${reference}`
  );

  // Add your logic here (e.g., update the database or subscription status)
}

// ======================
// Start Server
// ======================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});