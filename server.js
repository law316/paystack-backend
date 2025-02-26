const express = require("express");
const cors = require("cors");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const admin = require("firebase-admin");
require("dotenv").config(); // Load environment variables from .env file

// ======================
// Initialize Firebase
// ======================
if (!admin.apps.length) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

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

// Middleware configuration
app.use(cors());
app.use(express.json()); // Parse JSON for all routes except /webhook
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded data

// Rate limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(apiLimiter);

// ======================
// /create-access-code Route
// ======================
app.post("/create-access-code", async (req, res) => {
  try {
    const { email, amount } = req.body;

    // Validate inputs
    if (!email || !amount) {
      return res.status(400).json({ error: "Email and amount are required." });
    }

    // Make a request to Paystack to create an access code
    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email,
        amount: amount * 100, // Convert to kobo (Paystack expects amount in kobo)
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`, // Use Paystack secret key
          "Content-Type": "application/json",
        },
      }
    );

    // Return the access code and other details to the client
    const { data } = response;
    return res.status(200).json({
      status: "success",
      access_code: data.data.access_code,
      authorization_url: data.data.authorization_url,
      reference: data.data.reference,
    });
  } catch (error) {
    console.error("🚨 Error creating access code:", error.response?.data || error.message);
    return res.status(500).json({
      error: "Failed to create access code. Please try again later.",
    });
  }
});

// ======================
// Webhook Route
// ======================
app.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const secretKey = process.env.PAYSTACK_SECRET_KEY;
    const signature = req.headers["x-paystack-signature"];
    const rawBody = req.body; // Raw body is used here

    // Verify the webhook signature
    if (!signature) {
      return res.status(403).send("Forbidden: Missing signature");
    }

    const expectedSignature = crypto
      .createHmac("sha512", secretKey)
      .update(rawBody) // Use rawBody here for accurate signature verification
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

      // Handle subscription logic
      const subscriptionStartDate = paid_at ? new Date(paid_at) : new Date();
      const subscriptionEndDate = new Date(subscriptionStartDate);
      subscriptionEndDate.setMonth(subscriptionEndDate.getMonth() + 1);

      const formattedStartDate = subscriptionStartDate.toISOString().split("T")[0];
      const formattedEndDate = subscriptionEndDate.toISOString().split("T")[0];

      // Find user by email in Firebase Authentication
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