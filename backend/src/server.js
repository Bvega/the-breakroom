'use strict';
const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
require('dotenv').config();
const connectDB = require('./config/database');
const authRoutes = require('./routes/authRoutes');
const snapRoutes = require('./routes/snapRoutes');

// Connect to Database
connectDB();

const app = express();

// Middleware
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || 'http://localhost:5173' }));
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static — serve uploaded images (Phase 4)
app.use('/uploads', express.static(path.join(__dirname, '..', 'uploads')));

// Routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/snaps', snapRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', project: 'the-breakroom', phase: 4 });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports = app;

