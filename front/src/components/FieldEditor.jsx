import React, { useState, useEffect } from 'react';
import { TrashIcon } from 'lucide-react';

// Define the available field types and their corresponding sizes
const FIELD_TYPE_CONFIGS = [
  { type: 'int', size: 4 },
  { type: 'float', size: 4 },
  { type: 'char', size: 1 },
  { type: 'dynamic array', size: 0 },
  { type: 'array', size: null }, // Array type that will need element type and count
  { type: 'double', size: 8 },
  { type: 'bool', size: 1 },
  { type: 'long', size: 8},
  { type: 'short', size: 2},
  { type: 'bitfield', size: null },
  { type: 'custom', size: null },
];

const FieldEditor = ({ field, onFieldChange, onRemove, fields, index, customTypes = [] }) => {
  const [arrayType, setArrayType] = useState(field.arrayType || 'int');
  const [arrayCount, setArrayCount] = useState(field.arrayCount || 1);
  const [totalArraySize, setTotalArraySize] = useState('0');
  
  // Combine base field types with custom types
  const allFieldTypes = [
    ...FIELD_TYPE_CONFIGS,
    ...customTypes.map(customType => ({
      type: `custom:${customType.name}`,
      size: customType.totalSize || null,
      isCustomType: true,
      customTypeData: customType
    }))
  ];

  const handleTypeChange = (value) => {
    // Check if this is a custom type
    if (value.startsWith('custom:')) {
      // For custom types, set type and custom type info
      const customTypeName = value.replace('custom:', '');
      const customType = customTypes.find(t => t.name === customTypeName);
      
      onFieldChange('type', value);
      onFieldChange('customTypeName', customTypeName);
      
      // If we have size info for the custom type, use it
      if (customType && customType.totalSize) {
        onFieldChange('size', customType.totalSize.toString());
      } else {
        // Otherwise, calculate total size from fields
        const totalSize = calculateCustomTypeSize(customType);
        onFieldChange('size', totalSize.toString());
      }
    } else {
      // For standard types, use the original logic
      const selectedType = allFieldTypes.find((option) => option.type === value);
      onFieldChange('type', value);
      
      if (selectedType && selectedType.size !== null) {
        onFieldChange('size', selectedType.size.toString());
      } else if (value === 'array') {
        // For array type, we'll calculate the size based on element type and count
        calculateArraySize(arrayType, arrayCount);
      } else {
        onFieldChange('size', '');
      }
      
      // Clear custom type info if changing away from custom type
      if (field.customTypeName) {
        onFieldChange('customTypeName', '');
      }
      
      // Clear reference field if changing away from dynamic array
      if (value !== 'dynamic array') {
        onFieldChange('referenceField', '');
      }
    }
  };

  // Calculate size for a custom type by summing its fields
  const calculateCustomTypeSize = (customType) => {
    if (!customType || !customType.fields) return 0;
    
    let totalSize = 0;
    customType.fields.forEach(field => {
      if (field.size && !isNaN(parseInt(field.size))) {
        totalSize += parseInt(field.size);
      }
    });
    
    return totalSize;
  };

  // Calculate array size based on element type and count
  const calculateArraySize = (type, count) => {
    const elementType = allFieldTypes.find(t => t.type === type);
    if (elementType && elementType.size !== null) {
      const totalSize = elementType.size * count;
      setTotalArraySize(totalSize.toString());
      onFieldChange('size', totalSize.toString());
      onFieldChange('arrayType', type);
      onFieldChange('arrayCount', count);
    }
  };

  // Update array size when element type or count changes
  useEffect(() => {
    if (field.type === 'array') {
      calculateArraySize(arrayType, arrayCount);
    }
  }, [arrayType, arrayCount]);

  // Get available fields for reference (excluding the current field)
  const availableReferenceFields = fields
    ?.filter(f => 
      f.name !== field.name && 
      f.name.trim() !== ''
    )
    .map(f => f.name) || [];

  // Set a default reference field if none is selected and options are available
  useEffect(() => {
    if (field.type === 'dynamic array' && !field.referenceField && availableReferenceFields.length > 0) {
      onFieldChange('referenceField', availableReferenceFields[0]);
    }
  }, [field.type, field.referenceField, availableReferenceFields]);

  // Check if the current field type is a custom type
  const isCustomType = field.type && field.type.startsWith('custom:');

  return (
    <div className="mb-3 p-3 bg-gray-100 rounded-lg shadow-sm">
      {field.type === 'array' ? (
        // Special layout for array type - evenly distributed
        <div className="flex items-center space-x-3">
          {/* Field Name */}
          <div className="w-1/5">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Field Name
            </label>
            <input
              value={field.name}
              onChange={(e) => onFieldChange('name', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Enter name"
            />
          </div>

          {/* Field Type */}
          <div className="w-1/5">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Field Type
            </label>
            <select
              value={field.type}
              onChange={(e) => handleTypeChange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {/* Standard types */}
              <optgroup label="Standard Types">
                {FIELD_TYPE_CONFIGS.map((option) => (
                  <option key={option.type} value={option.type}>
                    {option.type}
                  </option>
                ))}
              </optgroup>
              
              {/* Custom types */}
              {customTypes.length > 0 && (
                <optgroup label="Custom Types">
                  {customTypes.map(type => (
                    <option key={`custom:${type.name}`} value={`custom:${type.name}`}>
                      {type.name}
                    </option>
                  ))}
                </optgroup>
              )}
            </select>
          </div>

          {/* Field Size */}
          <div className="w-1/5">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Field Size (bytes)
            </label>
            <input
              value={totalArraySize}
              readOnly
              className="w-full px-3 py-2 border border-gray-300 rounded-md bg-gray-100"
              placeholder="Size"
            />
          </div>

          {/* Array Element Type */}
          <div className="w-1/5">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Array Element Type
            </label>
            <select
              value={arrayType}
              onChange={(e) => {
                setArrayType(e.target.value);
                onFieldChange('arrayType', e.target.value);
              }}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {allFieldTypes.filter(t => 
                t.type !== 'array' && 
                t.type !== 'dynamic array' && 
                t.type !== 'bitfield' && 
                t.type !== 'custom'
              ).map((option) => (
                <option key={option.type} value={option.type}>
                  {option.isCustomType ? option.type.replace('custom:', '') : option.type}
                </option>
              ))}
            </select>
          </div>

          {/* Number of Elements */}
          <div className="w-1/5">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Number of Elements
            </label>
            <input
              type="number"
              min="1"
              value={arrayCount}
              onInput={(e) => {
                // Allow empty string but default to 1 when calculating
                const inputValue = e.target.value;
                const numValue = inputValue === '' ? 1 : Math.max(1, parseInt(inputValue) || 1);
                setArrayCount(inputValue === '' ? '' : numValue);
                onFieldChange('arrayCount', numValue);
              }}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {/* Remove Button */}
          <div className="w-12 flex-shrink-0">
            <label className="invisible block text-sm font-medium text-gray-700 mb-1">
              &nbsp;
            </label>
            <button
              onClick={onRemove}
              className="w-10 h-10 flex items-center justify-center bg-red-500 text-white rounded-full hover:bg-red-600 transition-colors"
              title="Remove Field"
            >
              <TrashIcon size={20} />
            </button>
          </div>
        </div>
      ) : field.type === 'dynamic array' ? (
        // Layout for dynamic array
        <div className="flex items-center space-x-3">
          {/* Field Name */}
          <div className="w-1/4">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Field Name
            </label>
            <input
              value={field.name}
              onChange={(e) => onFieldChange('name', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Enter name"
            />
          </div>

          {/* Field Type */}
          <div className="w-1/4">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Field Type
            </label>
            <select
              value={field.type}
              onChange={(e) => handleTypeChange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {/* Standard types */}
              <optgroup label="Standard Types">
                {FIELD_TYPE_CONFIGS.map((option) => (
                  <option key={option.type} value={option.type}>
                    {option.type}
                  </option>
                ))}
              </optgroup>
              
              {/* Custom types */}
              {customTypes.length > 0 && (
                <optgroup label="Custom Types">
                  {customTypes.map(type => (
                    <option key={`custom:${type.name}`} value={`custom:${type.name}`}>
                      {type.name}
                    </option>
                  ))}
                </optgroup>
              )}
            </select>
          </div>

          {/* Field Size */}
          <div className="w-1/4">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Field Size (bytes)
            </label>
            <input
              value="undefined"
              readOnly
              className="w-full px-3 py-2 border border-gray-300 rounded-md bg-gray-100"
              placeholder="Size"
            />
          </div>

          {/* Length Field */}
          <div className="w-1/4">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Length Field
            </label>
            <select
              value={field.referenceField}
              onChange={(e) => onFieldChange('referenceField', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Select length field</option>
              {availableReferenceFields.map((fieldName) => (
                <option key={fieldName} value={fieldName}>
                  {fieldName}
                </option>
              ))}
            </select>
          </div>

          {/* Remove Button */}
          <div className="w-12 flex-shrink-0">
            <label className="invisible block text-sm font-medium text-gray-700 mb-1">
              &nbsp;
            </label>
            <button
              onClick={onRemove}
              className="w-10 h-10 flex items-center justify-center bg-red-500 text-white rounded-full hover:bg-red-600 transition-colors"
              title="Remove Field"
            >
              <TrashIcon size={20} />
            </button>
          </div>
        </div>
      ) : isCustomType ? (
        // Layout for custom type fields
        <div className="flex items-center space-x-3">
          {/* Field Name */}
          <div className="w-1/3">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Field Name
            </label>
            <input
              value={field.name}
              onChange={(e) => onFieldChange('name', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Enter name"
            />
          </div>

          {/* Field Type */}
          <div className="w-1/3">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Field Type
            </label>
            <select
              value={field.type}
              onChange={(e) => handleTypeChange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-indigo-50"
            >
              {/* Standard types */}
              <optgroup label="Standard Types">
                {FIELD_TYPE_CONFIGS.map((option) => (
                  <option key={option.type} value={option.type}>
                    {option.type}
                  </option>
                ))}
              </optgroup>
              
              {/* Custom types */}
              {customTypes.length > 0 && (
                <optgroup label="Custom Types">
                  {customTypes.map(type => (
                    <option key={`custom:${type.name}`} value={`custom:${type.name}`}>
                      {type.name}
                    </option>
                  ))}
                </optgroup>
              )}
            </select>
          </div>

          {/* Field Size */}
          <div className="w-1/3">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Field Size (bytes)
            </label>
            <input
              value={field.size}
              readOnly
              className="w-full px-3 py-2 border border-gray-300 rounded-md bg-gray-100"
              placeholder="Size"
            />
          </div>

          {/* Remove Button */}
          <div className="w-12 flex-shrink-0">
            <label className="invisible block text-sm font-medium text-gray-700 mb-1">
              &nbsp;
            </label>
            <button
              onClick={onRemove}
              className="w-10 h-10 flex items-center justify-center bg-red-500 text-white rounded-full hover:bg-red-600 transition-colors"
              title="Remove Field"
            >
              <TrashIcon size={20} />
            </button>
          </div>
        </div>
      ) : (
        // Default layout for other types
        <div className="flex items-center space-x-3">
          {/* Field Name */}
          <div className="w-1/3">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Field Name
            </label>
            <input
              value={field.name}
              onChange={(e) => onFieldChange('name', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Enter name"
            />
          </div>

          {/* Field Type */}
          <div className="w-1/3">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Field Type
            </label>
            <select
              value={field.type}
              onChange={(e) => handleTypeChange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {/* Standard types */}
              <optgroup label="Standard Types">
                {FIELD_TYPE_CONFIGS.map((option) => (
                  <option key={option.type} value={option.type}>
                    {option.type}
                  </option>
                ))}
              </optgroup>
              
              {/* Custom types */}
              {customTypes.length > 0 && (
                <optgroup label="Custom Types">
                  {customTypes.map(type => (
                    <option key={`custom:${type.name}`} value={`custom:${type.name}`}>
                      {type.name}
                    </option>
                  ))}
                </optgroup>
              )}
            </select>
          </div>

          {/* Field Size */}
          <div className="w-1/3">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Field Size (bytes)
            </label>
            <input
              value={field.size}
              onChange={(e) => onFieldChange('size', e.target.value)}
              className={`w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 ${
                field.type === 'custom' || field.type === 'bitfield' ? 'focus:ring-blue-500' : 'bg-gray-100'
              }`}
              placeholder="Size"
              disabled={field.type !== 'custom' && field.type !== 'bitfield'}
            />
          </div>

          {/* Remove Button */}
          <div className="w-12 flex-shrink-0">
            <label className="invisible block text-sm font-medium text-gray-700 mb-1">
              &nbsp;
            </label>
            <button
              onClick={onRemove}
              className="w-10 h-10 flex items-center justify-center bg-red-500 text-white rounded-full hover:bg-red-600 transition-colors"
              title="Remove Field"
            >
              <TrashIcon size={20} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default FieldEditor;