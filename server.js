const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const axios = require("axios");
require("dotenv").config(); // Load environment variables from .env file

// Initialize Express app
const app = express();

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors()); // Allow cross-origin requests

// Paystack secret key from environment variables
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

// ======================
// Root Route
// ======================
app.get("/", (req, res) => {
  res.send("Backend is running!");
});

// ======================
// Create Access Code Endpoint
// ======================
app.post("/create-access-code", async (req, res) => {
  try {
    const { email, amount } = req.body;

    // Make a request to Paystack to initialize a transaction
    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      { email, amount }, // `amount` is in kobo (e.g., ₦100 = 10000 kobo)
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    // Respond back with the access code and reference
    res.status(200).json({
      status: true,
      access_code: response.data.data.access_code,
      reference: response.data.data.reference,
    });
  } catch (error) {
    console.error("Error creating access code:", error.message);
    res.status(500).json({
      status: false,
      message: "Failed to create access code",
    });
  }
});

// ======================
// Verify Transaction Endpoint
// ======================
app.post("/verify-transaction", async (req, res) => {
  try {
    const { reference } = req.body;

    // Make a request to Paystack to verify the transaction
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    // Check the transaction status
    if (response.data.data.status === "success") {
      res.status(200).json({
        status: true,
        message: "Transaction verified successfully",
        data: response.data.data,
      });
    } else {
      res.status(400).json({
        status: false,
        message: "Transaction verification failed",
      });
    }
  } catch (error) {
    console.error("Error verifying transaction:", error.message);
    res.status(500).json({
      status: false,
      message: "Failed to verify transaction",
    });
  }
});

// ======================
// Start the Server
// ======================
const PORT = process.env.PORT || 10000; // Default port is 10000 (required by Render)
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});