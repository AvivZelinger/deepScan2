import React, { useState, useEffect } from 'react';
import { Plus, X, Save, Edit, Trash, Eye, ChevronDown, ChevronRight } from 'lucide-react';

const BASE_URL = 'http://localhost:8383';

// Define the available field types and their corresponding sizes
const FIELD_TYPE_CONFIGS = [
  { type: 'int', size: 4 },
  { type: 'float', size: 4 },
  { type: 'char', size: 1 },
  { type: 'double', size: 8 },
  { type: 'bool', size: 1 },
  { type: 'long', size: 8},
  { type: 'short', size: 2},
  { type: 'bitfield', size: null },
  { type: 'array', size: null }, // Added array type
];

// Field component for the custom type definition
const TypeFieldEditor = ({ field, onFieldChange, onRemove }) => {
  // Keep local state in sync with props
  const [localType, setLocalType] = useState(field.type || 'int');
  const [arrayType, setArrayType] = useState(field.arrayType || 'int');
  const [arrayCount, setArrayCount] = useState(field.arrayCount || 1);
  const [arraySize, setArraySize] = useState(field.size || '0');

  // Update local state when props change
  useEffect(() => {
    setLocalType(field.type || 'int');
    setArrayType(field.arrayType || 'int');
    setArrayCount(field.arrayCount || 1);
    setArraySize(field.size || '0');
  }, [field]);

  // Calculate array size based on element type and count
  const calculateArraySize = (type, count) => {
    const elementType = FIELD_TYPE_CONFIGS.find(t => t.type === type);
    if (elementType && elementType.size !== null) {
      const totalSize = elementType.size * count;
      setArraySize(totalSize.toString());
      onFieldChange('size', totalSize.toString());
      onFieldChange('arrayType', type);
      onFieldChange('arrayCount', count);
    }
  };

  // Update array size when element type or count changes
  useEffect(() => {
    if (localType === 'array') {
      calculateArraySize(arrayType, arrayCount);
    }
  }, [arrayType, arrayCount, localType]);

  const handleTypeChange = (value) => {
    // Update local state first
    setLocalType(value);
    
    // Then update parent component state
    onFieldChange('type', value);
    
    // Set appropriate size based on type
    const typeConfig = FIELD_TYPE_CONFIGS.find(t => t.type === value);
    if (typeConfig && typeConfig.size !== null) {
      onFieldChange('size', typeConfig.size.toString());
    } else if (value === 'array') {
      // For array type, we'll calculate the size based on element type and count
      calculateArraySize(arrayType, arrayCount);
    } else if (value === 'bitfield') {
      onFieldChange('size', '');
    }
  };

  const handleArrayTypeChange = (value) => {
    setArrayType(value);
    calculateArraySize(value, arrayCount);
  };

  const handleArrayCountChange = (value) => {
    const numValue = Math.max(1, parseInt(value) || 1);
    setArrayCount(numValue);
    calculateArraySize(arrayType, numValue);
  };

  return (
    <div className="flex items-center space-x-3 mb-3 p-3 bg-gray-50 rounded-lg">
      {localType === 'array' ? (
        // Special layout for array type
        <>
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
              value={localType}
              onChange={(e) => handleTypeChange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {FIELD_TYPE_CONFIGS.map((option) => (
                <option key={option.type} value={option.type}>
                  {option.type}
                </option>
              ))}
            </select>
          </div>

          {/* Field Size (calculated) */}
          <div className="w-1/5">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Field Size (bytes)
            </label>
            <input
              value={arraySize}
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
              onChange={(e) => handleArrayTypeChange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {FIELD_TYPE_CONFIGS.filter(t => 
                t.type !== 'array' && t.type !== 'bitfield'
              ).map((option) => (
                <option key={option.type} value={option.type}>
                  {option.type}
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
              onChange={(e) => handleArrayCountChange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {/* Remove Button */}
          <div className="flex-shrink-0">
            <button
              onClick={onRemove}
              className="w-10 h-10 flex items-center justify-center bg-red-500 text-white rounded-full hover:bg-red-600 transition-colors"
              title="Remove Field"
            >
              <Trash size={18} />
            </button>
          </div>
        </>
      ) : (
        // Standard layout for non-array fields
        <>
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
              value={localType}
              onChange={(e) => handleTypeChange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {FIELD_TYPE_CONFIGS.map((option) => (
                <option key={option.type} value={option.type}>
                  {option.type}
                </option>
              ))}
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
                localType === 'bitfield' ? 'focus:ring-blue-500' : 'bg-gray-100'
              }`}
              placeholder="Size"
              disabled={localType !== 'bitfield'}
            />
          </div>

          {/* Remove Button */}
          <div className="flex-shrink-0">
            <button
              onClick={onRemove}
              className="w-10 h-10 flex items-center justify-center bg-red-500 text-white rounded-full hover:bg-red-600 transition-colors"
              title="Remove Field"
            >
              <Trash size={18} />
            </button>
          </div>
        </>
      )}
    </div>
  );
};

// Custom Type Item component for the list view
const CustomTypeItem = ({ type, onEdit, onDelete, onSelect }) => {
  const [expanded, setExpanded] = useState(false);

  // Helper to format field details, including array info
  const formatFieldDetails = (field) => {
    if (field.type === 'array') {
      return `${field.type} of ${field.arrayType || 'int'} [${field.arrayCount || 1}]`;
    }
    return field.type;
  };

  return (
    <div className="border border-gray-200 rounded-lg mb-3 overflow-hidden">
      <div className="flex items-center justify-between p-3 bg-white hover:bg-gray-50">
        <div className="flex items-center flex-1" onClick={() => setExpanded(!expanded)} style={{ cursor: 'pointer' }}>
          {expanded ? <ChevronDown size={18} className="mr-2 text-gray-500" /> : <ChevronRight size={18} className="mr-2 text-gray-500" />}
          <span className="font-medium text-gray-800">{type.name}</span>
          <span className="ml-3 px-2 py-1 bg-indigo-50 text-indigo-600 text-xs rounded-full">{type.fields?.length || 0} fields</span>
          {type.totalSize && (
            <span className="ml-2 px-2 py-1 bg-green-50 text-green-600 text-xs rounded-full">{type.totalSize} bytes</span>
          )}
        </div>
        <div className="flex space-x-2">
          <button 
            onClick={() => onSelect(type)} 
            className="flex items-center px-2 py-1 bg-indigo-50 text-indigo-600 rounded-md hover:bg-indigo-100 transition-colors"
            title="Use this type"
          >
            <Eye size={16} className="mr-1" />
            <span className="text-xs">Select</span>
          </button>
          <button 
            onClick={() => onEdit(type)} 
            className="flex items-center px-2 py-1 bg-blue-50 text-blue-600 rounded-md hover:bg-blue-100 transition-colors"
            title="Edit type"
          >
            <Edit size={16} className="mr-1" />
            <span className="text-xs">Edit</span>
          </button>
          <button 
            onClick={() => onDelete(type)}
            className="flex items-center px-2 py-1 bg-red-50 text-red-600 rounded-md hover:bg-red-100 transition-colors"
            title="Delete type"
          >
            <Trash size={16} className="mr-1" />
            <span className="text-xs">Delete</span>
          </button>
        </div>
      </div>
      
      {expanded && (
        <div className="p-3 bg-gray-50 border-t border-gray-200">
          <h4 className="text-sm font-medium text-gray-700 mb-2">Fields:</h4>
          <div className="space-y-2">
            {type.fields && type.fields.map((field, index) => (
              <div key={index} className="flex items-center p-2 bg-white rounded border border-gray-200">
                <span className="font-medium text-gray-700 mr-3">{field.name}</span>
                <span className="px-2 py-0.5 bg-blue-50 text-blue-600 text-xs rounded-full">
                  {formatFieldDetails(field)}
                </span>
                {field.size && (
                  <span className="ml-2 px-2 py-0.5 bg-gray-100 text-gray-600 text-xs rounded-full">
                    {field.size} bytes
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// Main CustomTypesManager component
const CustomTypesManager = ({ isOpen, onClose, onTypeSelect, existingTypes = [] }) => {
  const [customTypes, setCustomTypes] = useState([]);
  const [currentType, setCurrentType] = useState(null);
  const [typeName, setTypeName] = useState('');
  const [fields, setFields] = useState([{ name: '', type: 'int', size: '4' }]);
  const [view, setView] = useState('list'); // 'list' or 'edit'
  const [loading, setLoading] = useState(false);

  // Load custom types on mount
  useEffect(() => {
    if (isOpen) {
      fetchCustomTypes();
    }
  }, [isOpen]);

  // Initialize existing types if provided
  useEffect(() => {
    if (existingTypes.length > 0) {
      setCustomTypes(existingTypes);
    }
  }, [existingTypes]);

  const fetchCustomTypes = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${BASE_URL}/custom-types`);
      if (!response.ok) throw new Error('Failed to fetch custom types');
      const data = await response.json();
      
      // Ensure each type has a properly formatted fields array
      const formattedTypes = data.map(type => ({
        ...type,
        fields: Array.isArray(type.fields) ? type.fields : []
      }));
      
      setCustomTypes(formattedTypes);
    } catch (error) {
      console.error('Error fetching custom types:', error);
      // If we can't fetch, use the existing types
      if (existingTypes.length > 0) {
        setCustomTypes(existingTypes);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleCreateType = () => {
    setCurrentType(null);
    setTypeName('');
    setFields([{ name: '', type: 'int', size: '4' }]);
    setView('edit');
  };

  const handleEditType = (type) => {
    setCurrentType(type);
    setTypeName(type.name);
    
    // Make sure to process the fields to ensure they have all required properties
    const processedFields = type.fields.map(field => ({
      name: field.name || '',
      type: field.type || 'int',
      size: field.size || '4',
      arrayType: field.arrayType,
      arrayCount: field.arrayCount
    }));
    
    setFields(processedFields);
    setView('edit');
  };

  const handleDeleteType = async (type) => {
    if (!window.confirm(`Are you sure you want to delete the type "${type.name}"?`)) {
      return;
    }

    try {
      const response = await fetch(`${BASE_URL}/custom-types/${type._id}`, {
        method: 'DELETE',
      });

      if (!response.ok) throw new Error('Failed to delete custom type');
      
      // Update the list of custom types
      setCustomTypes(customTypes.filter(t => t._id !== type._id));
    } catch (error) {
      console.error('Error deleting custom type:', error);
      alert('Failed to delete custom type');
    }
  };

  const handleFieldChange = (index, key, value) => {
    setFields(prevFields => {
      const updatedFields = [...prevFields];
      updatedFields[index] = {
        ...updatedFields[index],
        [key]: value
      };
      return updatedFields;
    });
  };

  const handleAddField = () => {
    setFields([...fields, { name: '', type: 'int', size: '4' }]);
  };

  const handleRemoveField = (index) => {
    setFields(fields.filter((_, i) => i !== index));
  };

  const handleSaveType = async () => {
    // Validate fields
    if (!typeName.trim()) {
      alert('Type name is required');
      return;
    }

    // Check for duplicate type names
    if (!currentType && customTypes.some(t => t.name === typeName)) {
      alert(`A type with the name "${typeName}" already exists`);
      return;
    }

    // Validate all fields have names
    for (let i = 0; i < fields.length; i++) {
      if (!fields[i].name.trim()) {
        alert(`Field ${i + 1} requires a name`);
        return;
      }
    }

    // Create the data object - preserve array-specific properties
    const typeData = {
      name: typeName,
      fields: fields.map(field => {
        const fieldData = {
          name: field.name,
          type: field.type,
          size: field.size || '0'
        };
        
        // Add array-specific properties if it's an array
        if (field.type === 'array') {
          fieldData.arrayType = field.arrayType || 'int';
          fieldData.arrayCount = field.arrayCount || 1;
        }
        
        return fieldData;
      })
    };

    console.log('Sending data:', typeData);

    try {
      const url = currentType 
        ? `${BASE_URL}/custom-types/${currentType._id}` 
        : `${BASE_URL}/custom-types`;
      
      const method = currentType ? 'PUT' : 'POST';
      
      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(typeData),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Server error');
      }
      
      const savedType = await response.json();
      
      // Update the list of custom types
      if (currentType) {
        setCustomTypes(customTypes.map(t => t._id === currentType._id ? savedType : t));
      } else {
        setCustomTypes([...customTypes, savedType]);
      }
      
      // Return to list view
      setView('list');
    } catch (error) {
      console.error(`Error ${currentType ? 'updating' : 'creating'} custom type:`, error);
      alert(`Failed to ${currentType ? 'update' : 'create'} custom type: ${error.message}`);
    }
  };

  const handleSelectType = (type) => {
    onTypeSelect(type);
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-t-xl">
          <h2 className="text-xl font-semibold text-white">Custom Types Manager</h2>
          <button
            onClick={onClose}
            className="text-white hover:text-gray-200"
          >
            <X size={24} />
          </button>
        </div>
        
        {/* Content */}
        <div className="flex-1 overflow-auto p-4">
          {loading ? (
            <div className="flex items-center justify-center h-64">
              <div className="text-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500 mx-auto mb-4"></div>
                <p className="text-gray-600">Loading custom types...</p>
              </div>
            </div>
          ) : view === 'list' ? (
            <div className="space-y-4">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-medium text-gray-800">Available Custom Types</h3>
                <button
                  onClick={handleCreateType}
                  className="flex items-center space-x-2 px-3 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors"
                >
                  <Plus size={18} />
                  <span>Create New Type</span>
                </button>
              </div>
              
              {customTypes.length > 0 ? (
                <div>
                  {customTypes.map((type) => (
                    <CustomTypeItem
                      key={type._id || type.name}
                      type={type}
                      onEdit={handleEditType}
                      onDelete={handleDeleteType}
                      onSelect={handleSelectType}
                    />
                  ))}
                </div>
              ) : (
                <div className="text-center py-12 bg-gray-50 rounded-lg border border-gray-200">
                  <p className="text-gray-500 mb-4">No custom types defined yet</p>
                  <button
                    onClick={handleCreateType}
                    className="flex items-center space-x-2 px-3 py-2 bg-indigo-500 text-white rounded-lg hover:bg-indigo-600 transition-colors mx-auto"
                  >
                    <Plus size={18} />
                    <span>Create Your First Type</span>
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <h3 className="text-lg font-medium text-gray-800">
                {currentType ? `Edit Type: ${currentType.name}` : 'Create New Type'}
              </h3>
              
              <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-sm">
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Type Name
                </label>
                <input
                  type="text"
                  value={typeName}
                  onChange={(e) => setTypeName(e.target.value)}
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Enter type name"
                />
              </div>
              
              <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-sm">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="text-sm font-medium text-gray-700">Type Fields</h4>
                  <button
                    onClick={handleAddField}
                    className="flex items-center space-x-1 px-2 py-1 bg-indigo-50 text-indigo-600 rounded-md hover:bg-indigo-100 transition-colors"
                  >
                    <Plus size={16} />
                    <span className="text-sm">Add Field</span>
                  </button>
                </div>
                
                <div className="space-y-2">
                  {fields.map((field, index) => (
                    <TypeFieldEditor
                      key={index}
                      field={field}
                      onFieldChange={(key, value) => handleFieldChange(index, key, value)}
                      onRemove={() => handleRemoveField(index)}
                    />
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
        
        {/* Footer */}
        <div className="p-4 border-t border-gray-200 bg-gray-50 rounded-b-xl">
          {view === 'edit' ? (
            <div className="flex justify-between">
              <button
                onClick={() => setView('list')}
                className="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveType}
                className="flex items-center space-x-2 px-4 py-2 bg-indigo-500 text-white rounded-md hover:bg-indigo-600 transition-colors"
              >
                <Save size={18} />
                <span>Save Type</span>
              </button>
            </div>
          ) : (
            <button
              onClick={onClose}
              className="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300 transition-colors"
            >
              Close
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default CustomTypesManager;