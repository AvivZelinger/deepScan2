const mongoose = require('mongoose');

// Define field schema first to ensure proper typing
const fieldSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  type: {
    type: String,
    required: true
  },
  size: {
    type: String,
    required: true
  }
}, { _id: false }); // Don't create _id for each field

// Define Custom Type Schema
const customTypeSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  fields: [fieldSchema], // Use the field schema for proper validation
  // Calculate total size of the custom type in bytes
  totalSize: {
    type: Number,
    default: function() {
      if (!this.fields || this.fields.length === 0) return 0;
      
      return this.fields.reduce((total, field) => {
        const size = parseInt(field.size);
        return total + (isNaN(size) ? 0 : size);
      }, 0);
    }
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update the totalSize whenever fields are modified
customTypeSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  
  if (this.fields && this.fields.length > 0) {
    this.totalSize = this.fields.reduce((total, field) => {
      const size = parseInt(field.size);
      return total + (isNaN(size) ? 0 : size);
    }, 0);
  } else {
    this.totalSize = 0;
  }
  
  next();
});

// Create model
const CustomType = mongoose.model('CustomType', customTypeSchema);

module.exports = CustomType;