const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
require("dotenv").config(); // For environment variables like your Paystack secret key

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Allow cross-origin requests (important if your frontend or app is hosted elsewhere)
const cors = require("cors");
app.use(cors());

// Paystack secret key (loaded from .env file)
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

// ======================
// Create Access Code Endpoint
// ======================
app.post("/create-access-code", async (req, res) => {
  try {
    const { email, amount } = req.body;

    // Request Paystack to create a transaction and generate an access code
    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      { email, amount }, // Amount is in kobo (e.g., ₦100 = 10000 kobo)
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    // Respond with the access code
    res.status(200).json({
      status: true,
      access_code: response.data.data.access_code,
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

    // Request Paystack to verify the transaction
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    // Check transaction status
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
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});