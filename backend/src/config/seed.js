const mongoose = require('mongoose');
const connectDB = require('./database');
const User = require('../models/User');
const Company = require('../models/Company');
require('dotenv').config();

const seed = async () => {
  try {
    await connectDB();

    // Clear existing users and companies
    await User.deleteMany({});
    await Company.deleteMany({});

    // Create test companies
    await Company.create({
      domain_name: 'stripe.com',
      display_name: 'Stripe'
    });

    await Company.create({
      domain_name: 'notion.so',
      display_name: 'Notion'
    });

    // Create test user (email will be hashed automatically by User model pre-save hook)
    await User.create({
      personal_email: 'testuser@example.com',
      display_name: 'Test User',
      avatar_url: 'https://example.com/avatar.png'
    });

    console.log('Seed complete');
    process.exit(0);
  } catch (error) {
    console.error('Seed failed:', error);
    process.exit(1);
  }
};

seed();
