const express = require("express");
const cors = require("cors");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
require("dotenv").config();

// Initialize Express app
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

const updateUserSubscription = async (reference) => {
  // Implement Firebase/Database update here
  console.log(`Updating subscription for reference: ${reference}`);
};

// ======================
// Routes
// ======================
app.get("/", (req, res) => {
  res.send("Backend is running!");
});

app.post("/create-access-code", async (req, res) => {
  try {
    const { email: rawEmail, amount } = req.body;
    const email = sanitizeEmail(rawEmail);

    if (!email || !amount) {
      return res.status(400).json({
        status: false,
        message: "Email and amount are required.",
      });
    }

    if (typeof amount !== "number" || amount <= 0) {
      return res.status(400).json({
        status: false,
        message: "Amount must be a positive number.",
      });
    }

    const amountInKobo = amount * 100;
    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      { email, amount: amountInKobo },
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    res.status(200).json({
      status: true,
      access_code: response.data.data.access_code,
      reference: response.data.data.reference,
    });

  } catch (error) {
    console.error("Create error:", error.response?.data || error.message);
    res.status(500).json({
      status: false,
      message: "Payment initiation failed",
    });
  }
});

app.post("/verify-transaction", async (req, res) => {
  try {
    const { reference } = req.body;

    if (!reference) {
      return res.status(400).json({
        status: false,
        message: "Transaction reference required.",
      });
    }

    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    if (response.data.data.status === "success") {
      return res.status(200).json({
        status: true,
        message: "Transaction verified",
        data: response.data.data,
      });
    }

    return res.status(400).json({
      status: false,
      message: "Payment verification failed",
    });

  } catch (error) {
    console.error("Verify error:", error.response?.data || error.message);
    return res.status(500).json({
      status: false,
      message: "Verification failed",
      error: error.message
    });
  }
});

app.post("/webhook", async (req, res) => {
  try {
    const signature = req.headers["x-paystack-signature"];
    
    if (!validateWebhook(signature, req.rawBody)) {
      console.warn("Invalid signature");
      return res.sendStatus(403);
    }

    const event = JSON.parse(req.rawBody);
    
    if (event.event === "charge.success") {
      const reference = event.data.reference;
      console.log(`Processing payment: ${reference}`);
      await updateUserSubscription(reference);
    }

    res.sendStatus(200);

  } catch (error) {
    console.error("Webhook error:", error);
    res.status(400).json({
      status: false,
      message: "Webhook processing failed",
    });
  }
});

// ======================
// Server Configuration
// ======================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
});