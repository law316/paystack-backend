const express = require("express");
const cors = require("cors");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const admin = require("firebase-admin");
require("dotenv").config();

// Initialize Firebase
const serviceAccount = require("./serviceAccountKey.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DB_URL
});

// Initialize Express
const app = express();

// ======================
// Security Middleware
// ======================
app.use(
  "/webhook",
  express.raw({ type: "application/json" }),
  (req, res, next) => {
    req.rawBody = req.body.toString();
    next();
  }
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(apiLimiter);

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
    throw error;
  }
};

// ======================
// Enhanced Routes
// ======================
app.post("/create-access-code", async (req, res) => {
  try {
    const { email: rawEmail, amount } = req.body;
    const email = sanitizeEmail(rawEmail);

    // Validation
    if (!email || !amount || typeof amount !== "number" || amount <= 0) {
      return res.status(400).json({
        status: false,
        message: "Valid email and positive amount required"
      });
    }

    // Convert to kobo
    const amountInKobo = amount * 100;
    
    // Create Paystack transaction
    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email,
        amount: amountInKobo,
        callback_url: `${process.env.BASE_URL}/webhook`
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    res.status(200).json({
      status: true,
      data: {
        authorization_url: response.data.data.authorization_url,
        access_code: response.data.data.access_code,
        reference: response.data.data.reference
      }
    });

  } catch (error) {
    console.error("Payment error:", error.response?.data || error.message);
    res.status(500).json({
      status: false,
      message: process.env.NODE_ENV === "development" 
        ? error.message 
        : "Payment initialization failed"
    });
  }
});

app.post("/verify-transaction", async (req, res) => {
  try {
    const { reference, email } = req.body;
    
    if (!reference || !email) {
      return res.status(400).json({
        status: false,
        message: "Reference and email required"
      });
    }

    // Verify with Paystack
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    if (response.data.data.status === "success") {
      // Update Firebase
      await updateUserSubscription(reference, email);
      return res.json({
        status: true,
        data: response.data.data
      });
    }

    return res.status(400).json({
      status: false,
      message: response.data.message || "Payment verification failed"
    });

  } catch (error) {
    console.error("Verification error:", error.message);
    res.status(500).json({
      status: false,
      message: "Transaction verification failed"
    });
  }
});

app.post("/webhook", async (req, res) => {
  try {
    // Validate signature
    const signature = req.headers["x-paystack-signature"];
    if (!validateWebhook(signature, req.rawBody)) {
      console.warn("Invalid webhook signature");
      return res.sendStatus(403);
    }

    const event = JSON.parse(req.rawBody);
    
    // Handle successful charges
    if (event.event === "charge.success") {
      const { reference, customer } = event.data;
      console.log(`Processing payment ${reference} for ${customer.email}`);
      
      // Double-check with Paystack
      const verification = await axios.get(
        `https://api.paystack.co/transaction/verify/${reference}`,
        {
          headers: {
            Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          },
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
    res.status(500).json({
      status: false,
      message: "Webhook processing failed"
    });
  }
});

// ======================
// Server Configuration
// ======================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV || "development"} mode`);
  console.log(`Listening on port ${PORT}`);
});