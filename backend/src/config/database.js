const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

let mongoServer;

const connectDB = async () => {
  // If already connected, return
  if (mongoose.connection.readyState === 1) {
    return;
  }

  try {
    // Attempt to connect to the configured MONGO_URI with a short timeout
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 2000
    });
    console.log(`MongoDB Connected: ${mongoose.connection.host}`);
  } catch (error) {
    console.warn(`Local MongoDB connection failed: ${error.message}. Starting in-memory MongoDB server...`);
    
    try {
      // Start MongoMemoryServer on default port 27017
      mongoServer = await MongoMemoryServer.create({
        instance: {
          port: 27017,
          dbName: 'the-breakroom'
        }
      });
      
      const uri = mongoServer.getUri();
      await mongoose.connect(uri);
      console.log(`In-Memory MongoDB Connected: ${uri}`);
    } catch (memError) {
      console.error(`Failed to start in-memory MongoDB: ${memError.message}`);
      process.exit(1);
    }
  }
};

module.exports = connectDB;
