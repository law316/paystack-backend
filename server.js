const express = require("express");
const cors = require("cors");
const axios = require("axios");
require("dotenv").config(); // Load environment variables from .env file

// Initialize Express app
const app = express();

// Middleware
app.use(express.json()); // Parse JSON request body
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded request body
app.use(cors()); // Enable cross-origin requests

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
  console.log("Request Body:", req.body); // Log the request body

  const { email, amount } = req.body;

  // Validate email and amount
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

  try {
    // Convert amount to kobo
    const amountInKobo = amount * 100;

    // Make a request to Paystack to initialize a transaction
    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      { email, amount: amountInKobo }, // `amount` in kobo
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
    // Log the detailed error for debugging
    console.error("Error creating access code:", error.response?.data || error.message);

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
  const { reference } = req.body;

  // Check if the reference is provided
  if (!reference) {
    return res.status(400).json({
      status: false,
      message: "Transaction reference is required.",
    });
  }

  try {
    // Make a request to Paystack to verify the transaction
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`, // Ensure you have the correct secret key in your .env file
        },
      }
    );

    if (response.data.data.status === "success") {
      // Transaction was successful
      return res.status(200).json({
        status: true,
        message: "Transaction verified successfully",
        data: response.data.data, // Include transaction details
      });
    } else {
      // Transaction failed or is pending
      return res.status(400).json({
        status: false,
        message: "Transaction verification failed",
      });
    }
  } catch (error) {
    console.error("Error verifying transaction:", error.response?.data || error.message);
    return res.status(500).json({
      status: false,
      message: "An error occurred during transaction verification.",
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