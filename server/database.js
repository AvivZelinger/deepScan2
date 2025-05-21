const mongoose = require('mongoose');

// התחברות למסד הנתונים MongoDB
mongoose.connect('mongodb://localhost:27017/protocols')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Error connecting to MongoDB:', err));

module.exports = mongoose;
