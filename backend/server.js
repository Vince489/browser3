require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());

// Update CORS to allow VIRT protocol
app.use(cors({
  origin: function (origin, callback) {
    // allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    // allow localhost in development
    if (origin.startsWith('http://localhost')) return callback(null, true);

    // allow virt:// protocol
    if (origin.startsWith('virt://')) return callback(null, true);

    // allow electron protocols
    if (origin.startsWith('electron://') || origin.startsWith('app://')) return callback(null, true);

    // In production, restrict to specific origins
    if (process.env.NODE_ENV === 'production') {
      const allowedOrigins = ['electron://app', 'app://'];
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Not allowed by CORS'));
    }

    // For development, allow the request
    return callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI).then(() => {
  console.log('Connected to MongoDB');
}).catch((error) => {
  console.error('MongoDB connection error:', error);
});

// Basic route for testing
app.get('/', (req, res) => {
  res.json({ message: 'V12 Backend API is running' });
});

// API Routes
app.use('/api', require('./routes/sites'));

// Start server
app.listen(PORT, () => {
  console.log(`V12 Backend server running on port ${PORT}`);
});
