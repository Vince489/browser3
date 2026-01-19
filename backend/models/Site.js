const mongoose = require('mongoose');

const siteSchema = new mongoose.Schema({
  domain: {
    type: String,
    required: true,
    lowercase: true,
    minlength: 3,
    maxlength: 63,
    unique: true
  },
  tld: {
    type: String,
    required: true,
    enum: ['vc', 'vmc', 'at', 'lit']
  },
  target: {
    type: String,
    required: true,
    validate: {
      validator: function(v) {
        // Accept any HTTPS URL or IP address with optional port
        return /^https:\/\/.+/.test(v) ||
               /^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$/.test(v);
      },
      message: 'Target must be a valid HTTPS URL or IP address'
    }
  },
  // Replace owner with secretKeyHash for anonymous key-based authentication
  secretKeyHash: {
    type: String,
    required: true
  },
  title: {
    type: String,
    maxlength: 100
  },
  description: {
    type: String,
    maxlength: 500
  },
  verified: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastAccessed: {
    type: Date,
    default: Date.now
  },
  // For search functionality (Phase 4)
  keywords: [String],
  bodyText: String,
  indexedAt: {
    type: Date,
    default: Date.now
  }
});

// Create text index for search
siteSchema.index({
  title: 'text',
  description: 'text',
  bodyText: 'text',
  keywords: 'text'
}, {
  weights: {
    title: 10,
    keywords: 5,
    description: 3,
    bodyText: 1
  }
});

module.exports = mongoose.model('Site', siteSchema);
