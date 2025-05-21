const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// Schema for individual field analysis data
const DPIFieldSchema = new mongoose.Schema({
    is_dynamic_array: Boolean,
    min_size: Number,
    max_size: Number,
    min_value: mongoose.Schema.Types.Mixed,
    max_value: mongoose.Schema.Types.Mixed,
    size_defining_field: String,
    field_type: String,
    bitfields_count: Number
}, { _id: false });

// Schema for individual protocol fields
const FieldSchema = new mongoose.Schema({
    name: String,
    size: String,
    type: String,
    referenceField: String
});

// Use Mixed type for the DPI object to allow flexible structure
const ProtocolSchema = new mongoose.Schema({
    name: String,
    fields: [FieldSchema],
    files: [String],
    dpi: mongoose.Schema.Types.Mixed  // Use Mixed type instead of Map
});

const Protocol = mongoose.model('Protocol', ProtocolSchema);

module.exports = Protocol;