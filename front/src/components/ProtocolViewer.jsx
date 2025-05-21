import React, { useEffect, useState } from 'react';
import {
  DownloadIcon,
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  Server,
  FileType,
  Activity,
  Database,
  Package,
  Eye,
  Grid,
  Code
} from 'lucide-react';

const BASE_URL = 'http://localhost:8383';

// A more elegant field display component
const FieldViewer = ({ field }) => {
  // Handle null/undefined field
  if (!field) {
    return (
      <div className="p-4 mb-2 bg-white rounded-lg border border-gray-100 shadow-sm">
        <div className="text-sm text-gray-500">Field data unavailable</div>
      </div>
    );
  }

  // Get icon based on field type
  const getFieldIcon = (type) => {
    if (!type) return <Package className="text-gray-500" size={16} />;
    
    switch (type.toLowerCase()) {
      case 'int':
      case 'float':
      case 'double':
        return <Activity className="text-blue-500" size={16} />;
      case 'dynamic array':
        return <Code className="text-purple-500" size={16} />;
      case 'char':
      case 'char array':
        return <FileType className="text-green-500" size={16} />;
      case 'bool':
        return <Grid className="text-amber-500" size={16} />;
      case 'bitfield':
        return <Database className="text-indigo-500" size={16} />;
      default:
        return <Package className="text-gray-500" size={16} />;
    }
  };

  // Get the display size based on type
  const getDisplaySize = () => {
    if (!field.type) return 'Unknown';
    if (field.type === 'dynamic array') {
      return field.referenceField ? `Dynamic (based on ${field.referenceField})` : 'Dynamic';
    }
    if (field.type === 'array') {
      return field.size ? `${field.size} bytes` : 'Not specified';
    }
    return field.size ? `${field.size} bytes` : 'Not specified';
  };

  // Format array values for display
  const formatArrayValue = (value) => {
    if (!Array.isArray(value)) return value;
    
    if (value.length === 0) {
      return <span className="text-gray-400 italic">Empty array</span>;
    }
    
    // For small arrays (3 or fewer items), display them inline
    if (value.length <= 3) {
      return (
        <div className="flex flex-wrap gap-1">
          {value.map((item, index) => (
            <span key={index} className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-indigo-50 text-indigo-700">
              {typeof item === 'object' && item !== null ? 
                (Array.isArray(item) ? `[Array(${item.length})]` : '[Object]') : 
                String(item)}
            </span>
          ))}
        </div>
      );
    }
    
    // For larger arrays, create a collapsible table
    return (
      <div className="mt-1">
        <div className="flex items-center text-xs text-indigo-600 mb-1">
          <span>Array [{value.length} items]</span>
        </div>
        
        <div className="overflow-hidden rounded-md border border-gray-200">
          <table className="w-full table-auto text-xs">
            <tbody>
              {value.slice(0, 5).map((item, index) => (
                <tr key={index} className={index % 2 === 0 ? 'bg-gray-50' : 'bg-white'}>
                  <td className="px-2 py-1 font-mono text-xs text-gray-500 w-8">{index}</td>
                  <td className="px-2 py-1 text-gray-700">
                    {typeof item === 'object' && item !== null ? 
                      <span className="text-indigo-600">
                        {Array.isArray(item) ? `Array(${item.length})` : 'Object'}
                      </span> : 
                      String(item)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {value.length > 5 && (
            <div className="bg-indigo-50 px-2 py-1 text-xs text-indigo-700 text-center">
              + {value.length - 5} more items
            </div>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="p-4 mb-2 bg-white rounded-lg border border-gray-100 shadow-sm hover:shadow-md transition-all duration-200">
      <div className="flex items-center mb-3">
        {getFieldIcon(field.type)}
        <h3 className="ml-2 font-semibold text-gray-800">{field.name || 'Unnamed Field'}</h3>
      </div>
      
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-gray-50 p-2 rounded">
          <span className="text-xs text-gray-500 block mb-1">Type</span>
          <span className="font-medium text-gray-700">{field.type || 'Unknown'}</span>
        </div>
        
        <div className="bg-gray-50 p-2 rounded">
          <span className="text-xs text-gray-500 block mb-1">Size</span>
          <span className="font-medium text-gray-700">{getDisplaySize()}</span>
        </div>
      </div>

      {field.value !== undefined && (
        <div className="mt-3 bg-gray-50 p-2 rounded">
          <span className="text-xs text-gray-500 block mb-1">Value</span>
          <div className="font-medium text-gray-700">
            {Array.isArray(field.value) ? formatArrayValue(field.value) : field.value}
          </div>
        </div>
      )}
    </div>
  );
};

// Simplified protocol field display with null checks
// Protocol Field Component
const ProtocolField = ({ name, data }) => {
  const [expandedArrays, setExpandedArrays] = useState({});

  const toggleArrayExpansion = (fieldKey) => {
    setExpandedArrays(prev => ({
      ...prev,
      [fieldKey]: !prev[fieldKey]
    }));
  };

  const getValueColor = (value) => {
    if (typeof value === 'boolean') {
      return value ? 'text-emerald-600' : 'text-rose-600';
    }
    return 'text-slate-700';
  };

  const formatValue = (value, fieldKey) => {
    if (value === null || value === undefined) return 'null';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    
    // Handle array values with improved display
    if (Array.isArray(value)) {
      // Handle empty arrays
      if (value.length === 0) {
        return <span className="text-gray-500 italic text-xs">Empty array</span>;
      }
      
      // For small arrays (3 or fewer items), display them inline
      if (value.length <= 3) {
        return (
          <div className="flex flex-wrap gap-1">
            {value.map((item, index) => (
              <span key={index} className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-indigo-50 text-indigo-700">
                {typeof item === 'object' && item !== null ? 
                  (Array.isArray(item) ? `[Array(${item.length})]` : '[Object]') : 
                  String(item)}
              </span>
            ))}
          </div>
        );
      }
      
      // For larger arrays, create a collapsible table
      const isExpanded = expandedArrays[fieldKey] || false;
      const displayItems = isExpanded ? value : value.slice(0, 5);
      
      return (
        <div className="mt-1">
          <button 
            onClick={() => toggleArrayExpansion(fieldKey)}
            className="flex items-center text-xs text-indigo-600 hover:text-indigo-800 mb-1"
          >
            {isExpanded ? 
              <ChevronDown className="mr-1" size={14} /> : 
              <ChevronRight className="mr-1" size={14} />
            }
            <span>Array [{value.length} items]</span>
          </button>
          
          <div className="overflow-hidden rounded-md border border-gray-200">
            <table className="w-full table-auto text-xs">
              <tbody>
                {displayItems.map((item, index) => (
                  <tr key={index} className={index % 2 === 0 ? 'bg-gray-50' : 'bg-white'}>
                    <td className="px-2 py-1 font-mono text-xs text-gray-500 w-8">{index}</td>
                    <td className="px-2 py-1 text-gray-700">
                      {typeof item === 'object' && item !== null ? 
                        <span className="text-indigo-600">
                          {Array.isArray(item) ? `Array(${item.length})` : 'Object'}
                        </span> : 
                        String(item)
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!isExpanded && value.length > 5 && (
              <div className="bg-indigo-50 px-2 py-1 text-xs text-indigo-700 text-center">
                + {value.length - 5} more items
              </div>
            )}
          </div>
        </div>
      );
    }
    
    // Handle string that looks like an array (comma-separated values)
    if (typeof value === 'string' && value.includes(',') && 
        (value.match(/,/g) || []).length >= 2) {
      const items = value.split(',').map(item => item.trim()).filter(item => item);
      
      // Skip if it doesn't look like a real array after parsing
      if (items.length <= 1) return value.toString();
      
      // For small arrays (3 or fewer items), display them inline
      if (items.length <= 3) {
        return (
          <div className="flex flex-wrap gap-1">
            {items.map((item, index) => (
              <span key={index} className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-indigo-50 text-indigo-700">
                {item}
              </span>
            ))}
          </div>
        );
      }
      
      // For larger arrays, create a collapsible table
      const isExpanded = expandedArrays[fieldKey] || false;
      const displayItems = isExpanded ? items : items.slice(0, 5);
      
      return (
        <div className="mt-1">
          <button 
            onClick={() => toggleArrayExpansion(fieldKey)}
            className="flex items-center text-xs text-indigo-600 hover:text-indigo-800 mb-1"
          >
            {isExpanded ? 
              <ChevronDown className="mr-1" size={14} /> : 
              <ChevronRight className="mr-1" size={14} />
            }
            <span>Array [{items.length} items]</span>
          </button>
          
          <div className="overflow-hidden rounded-md border border-gray-200">
            <table className="w-full table-auto text-xs">
              <tbody>
                {displayItems.map((item, index) => (
                  <tr key={index} className={index % 2 === 0 ? 'bg-gray-50' : 'bg-white'}>
                    <td className="px-2 py-1 font-mono text-xs text-gray-500 w-8">{index}</td>
                    <td className="px-2 py-1 text-gray-700">{item}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!isExpanded && items.length > 5 && (
              <div className="bg-indigo-50 px-2 py-1 text-xs text-indigo-700 text-center">
                + {items.length - 5} more items
              </div>
            )}
          </div>
        </div>
      );
    }
    
    // For long strings, truncate them
    if (typeof value === 'string' && value.length > 50) {
      return (
        <div className="group relative">
          <span>{value.substring(0, 47)}...</span>
          <div className="hidden group-hover:block absolute bg-white p-2 border rounded shadow-lg z-10 left-0 -top-1 max-w-xs text-xs whitespace-normal">
            {value}
          </div>
        </div>
      );
    }
    
    return value.toString();
  };

  return (
    <div className="py-2 px-4 hover:bg-slate-50 transition-colors">
      <div className="flex items-start">
        <span className="text-sm font-medium text-slate-600 w-40">{name}</span>
        <div className="flex-1">
          {typeof data === 'object' && data !== null ? (
            <div className="grid grid-cols-2 gap-2">
              {Object.entries(data).map(([key, value]) => (
                <div key={key} className="flex items-start space-x-2">
                  <span className="text-sm text-slate-400 mt-0.5">{key}:</span>
                  <div className={`text-sm font-medium ${getValueColor(value)}`}>
                    {formatValue(value, `${name}-${key}`)}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <span className={`text-sm font-medium ${getValueColor(data)}`}>
              {formatValue(data, name)}
            </span>
          )}
        </div>
      </div>
    </div>
  );
};

// IP Protocol Card Component with null/undefined checks
const IPProtocolCard = ({ ip, fields, name }) => {
  const [isExpanded, setIsExpanded] = useState(true);
  const [currentPercentageIndex, setCurrentPercentageIndex] = useState(0);
  
  // Add safety check for fields
  if (!fields || typeof fields !== 'object') {
    return (
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden shadow-sm">
        <div className="border-b border-gray-200 bg-gradient-to-r from-indigo-50 to-white">
          <div className="flex items-center justify-between p-4">
            <div className="flex items-center space-x-2">
              <Server className="text-indigo-500" size={22} />
              <span className="font-semibold text-gray-800">{ip}</span>
            </div>
            <span className="px-3 py-1 bg-red-50 text-red-700 rounded-full text-xs font-medium">
              No fields data
            </span>
          </div>
        </div>
      </div>
    );
  }
  
  // Get percentages in descending order, ensuring 100% is first
  const percentages = Object.keys(fields).length > 0 ? 
    Object.keys(fields).sort((a, b) => {
      if (a === "100%") return -1;
      if (b === "100%") return 1;
      return parseFloat(b) - parseFloat(a);
    }) : [];
  
  // Handle case when no percentages are available
  if (percentages.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden shadow-sm">
        <div className="border-b border-gray-200 bg-gradient-to-r from-indigo-50 to-white">
          <div className="flex items-center justify-between p-4">
            <div className="flex items-center space-x-2">
              <Server className="text-indigo-500" size={22} />
              <span className="font-semibold text-gray-800">{ip}</span>
            </div>
            <span className="px-3 py-1 bg-amber-50 text-amber-700 rounded-full text-xs font-medium">
              No percentage data
            </span>
          </div>
        </div>
      </div>
    );
  }
  
  const currentPercentage = percentages[currentPercentageIndex];
  const currentFields = fields[currentPercentage] || {};
  
  const goToNextPercentage = (e) => {
    e.stopPropagation(); // Prevent expansion toggle
    setCurrentPercentageIndex((prev) => 
      (prev + 1) % percentages.length
    );
  };
  
  const goToPrevPercentage = (e) => {
    e.stopPropagation(); // Prevent expansion toggle
    setCurrentPercentageIndex((prev) => 
      (prev - 1 + percentages.length) % percentages.length
    );
  };

  const handleDownload = () => {
    // Updated to include the percentage parameter
    window.open(
      `${BASE_URL}/download-dissector?ip=${encodeURIComponent(ip)}&protocol=${name}&percentage=${encodeURIComponent(currentPercentage)}`,
      '_blank'
    );
  };
  
  // Count dynamic fields with null check
  const countDynamicFields = () => {
    if (!currentFields || typeof currentFields !== 'object') {
      return 0;
    }
    
    return Object.values(currentFields).filter(field => 
      field && (
        field.field_type === 'string/Code/Data' || 
        field.is_dynamic_array === true ||
        (field.size === 0 && field.reference_field)
      )
    ).length;
  };
  
  const dynamicFieldCount = countDynamicFields();
  
  // Group fields by category with null checks
  const groupFieldsByCategory = (fields) => {
    if (!fields || typeof fields !== 'object') {
      return { headers: {}, data: {}, metadata: {} };
    }
    
    const categories = {
      headers: {},
      data: {},
      metadata: {}
    };
    
    // Simple heuristic to categorize fields
    Object.entries(fields).forEach(([fieldName, fieldData]) => {
      if (!fieldData) return; // Skip if field data is null/undefined
      
      if (fieldName.toLowerCase().includes('header') || 
          fieldName.toLowerCase().includes('type') || 
          fieldName.toLowerCase().includes('version')) {
        categories.headers[fieldName] = fieldData;
      } else if (fieldName.toLowerCase().includes('data') || 
                fieldName.toLowerCase().includes('payload') || 
                fieldName.toLowerCase().includes('content') ||
                fieldName === 'message' ||
                fieldData.is_dynamic_array) {
        categories.data[fieldName] = fieldData;
      } else {
        categories.metadata[fieldName] = fieldData;
      }
    });
    
    return categories;
  };
  
  const groupedFields = groupFieldsByCategory(currentFields);
  
  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden shadow-sm hover:shadow-md transition-all duration-200">
      <div className="border-b border-gray-200 bg-gradient-to-r from-indigo-50 to-white">
        <div className="flex items-center justify-between p-4">
          <div
            className="flex items-center space-x-3 cursor-pointer flex-1"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? (
              <ChevronDown className="text-indigo-400" />
            ) : (
              <ChevronRight className="text-indigo-400" />
            )}
            <div className="flex items-center space-x-2">
              <Server className="text-indigo-500" size={22} />
              <span className="font-semibold text-gray-800">{ip}</span>
            </div>
          </div>
          
          {/* Percentage selector */}
          {percentages.length > 1 && (
            <div className="flex items-center mx-4">
              <button 
                onClick={goToPrevPercentage}
                className="p-1 bg-gray-100 rounded-l-md hover:bg-gray-200 transition-colors"
                title="Previous percentage"
              >
                <ChevronLeft size={16} className="text-gray-600" />
              </button>
              <div className="px-3 py-1 bg-indigo-100 text-indigo-800 font-medium text-sm">
                {currentPercentage}
              </div>
              <button 
                onClick={goToNextPercentage}
                className="p-1 bg-gray-100 rounded-r-md hover:bg-gray-200 transition-colors"
                title="Next percentage"
              >
                <ChevronRight size={16} className="text-gray-600" />
              </button>
            </div>
          )}
          
          <div className="flex items-center space-x-4">
            <span className="px-3 py-1 bg-indigo-50 text-indigo-700 rounded-full text-xs font-medium">
              {Object.keys(currentFields).length} Fields
            </span>
            {dynamicFieldCount > 0 && (
              <span className="px-3 py-1 bg-purple-50 text-purple-700 rounded-full text-xs font-medium">
                {dynamicFieldCount} Dynamic
              </span>
            )}
            <button
              onClick={handleDownload}
              className="flex items-center space-x-1 px-3 py-1.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-all duration-200 shadow-sm"
            >
              <DownloadIcon size={16} />
              <span className="text-sm font-medium">Download</span>
            </button>
          </div>
        </div>
      </div>
      
      {isExpanded && (
        <div className="p-4 bg-gray-50">
          {/* Show categorized fields */}
          {groupedFields.headers && Object.keys(groupedFields.headers).length > 0 && (
            <div className="mb-4">
              <h3 className="text-sm font-medium text-gray-500 mb-2 ml-1 flex items-center">
                <Database size={14} className="mr-1 text-indigo-400" />
                Headers
              </h3>
              <div className="space-y-1">
                {Object.entries(groupedFields.headers).map(([fieldName, fieldData]) => (
                  <ProtocolField key={fieldData._id || fieldName} name={fieldName} data={fieldData} />
                ))}
              </div>
            </div>
          )}
          
          {groupedFields.data && Object.keys(groupedFields.data).length > 0 && (
            <div className="mb-4">
              <h3 className="text-sm font-medium text-gray-500 mb-2 ml-1 flex items-center">
                <Code size={14} className="mr-1 text-indigo-400" />
                Data & Payload
              </h3>
              <div className="space-y-1">
                {Object.entries(groupedFields.data).map(([fieldName, fieldData]) => (
                  <ProtocolField key={fieldData._id || fieldName} name={fieldName} data={fieldData} />
                ))}
              </div>
            </div>
          )}
          
          {groupedFields.metadata && Object.keys(groupedFields.metadata).length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-gray-500 mb-2 ml-1 flex items-center">
                <Activity size={14} className="mr-1 text-indigo-400" />
                Additional Fields
              </h3>
              <div className="space-y-1">
                {Object.entries(groupedFields.metadata).map(([fieldName, fieldData]) => (
                  <ProtocolField key={fieldData._id || fieldName} name={fieldName} data={fieldData} />
                ))}
              </div>
            </div>
          )}
          
          {/* Show a message if no fields in any category */}
          {(!groupedFields.headers || Object.keys(groupedFields.headers).length === 0) && 
           (!groupedFields.data || Object.keys(groupedFields.data).length === 0) &&
           (!groupedFields.metadata || Object.keys(groupedFields.metadata).length === 0) && (
            <div className="text-center py-4">
              <p className="text-gray-500">No field data available for this percentage.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Redesigned Protocol Output Display with robust error handling
const ProtocolOutputDisplay = ({ dpi, name }) => {
  const handleGlobalDownload = () => {
    window.open(`${BASE_URL}/download-dissector?ip=Global&protocol=${name}`, '_blank');
  };

  // Convert dpi data into a more suitable format with comprehensive error handling
  const transformDpiData = () => {
    // If dpi is null or undefined, return an empty object
    if (!dpi) {
      return {};
    }
    
    // If dpi is already an object with IP keys (in the new format)
    if (!Array.isArray(dpi) && typeof dpi === 'object') {
      // Check if it has the expected structure (IP -> percentage -> fields)
      const result = {};
      let hasCorrectFormat = false;
      
      for (const [key, value] of Object.entries(dpi)) {
        if (typeof value === 'object' && value !== null) {
          // Check if value has percentage keys
          const percentageKeys = Object.keys(value).filter(k => k.includes('%'));
          
          if (percentageKeys.length > 0) {
            // Format is already correct (IP -> percentage -> fields)
            hasCorrectFormat = true;
            result[key] = value;
          } else {
            // Format is IP -> fields, we need to wrap in a "100%" key
            result[key] = { "100%": value };
          }
        }
      }
      
      if (hasCorrectFormat || Object.keys(result).length > 0) {
        return result;
      }
    }
    
    // Handle array format
    if (Array.isArray(dpi)) {
      const result = {};
      
      dpi.forEach(entry => {
        if (!entry || typeof entry !== 'object') return;
        
        const ip = entry.ip || 'unknown';
        
        // Check if entry has a fields property
        if (entry.fields) {
          // If there's a percentage property, use it; otherwise use "100%"
          const percentage = entry.percentage || "100%";
          
          if (!result[ip]) {
            result[ip] = {};
          }
          
          result[ip][percentage] = entry.fields;
        } else if (typeof entry === 'object' && !('fields' in entry)) {
          // Entry is directly the fields object (no nested fields property)
          if (!result[ip]) {
            result[ip] = {};
          }
          
          result[ip]["100%"] = entry;
        }
      });
      
      return result;
    }
    
    // Last resort: if we can't make sense of the data structure, return empty object
    console.warn('Could not transform DPI data into the expected format:', dpi);
    return {};
  };
  
  const transformedDpi = transformDpiData();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between pb-4 border-b border-gray-200">
        <h2 className="text-xl font-bold text-gray-800 flex items-center">
          <Eye className="mr-2 text-indigo-500" />
          Protocol Analysis Results
        </h2>
        <button
          onClick={handleGlobalDownload}
          className="flex items-center space-x-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-all duration-200 shadow-sm"
        >
          <DownloadIcon size={18} />
          <span>Download Global Dissector</span>
        </button>
      </div>
      {Object.keys(transformedDpi).length > 0 ? (
        <div className="grid gap-6">
          {Object.entries(transformedDpi).map(([ip, fields]) => (
            <IPProtocolCard
              key={ip}
              ip={ip}
              fields={fields}
              name={name}
            />
          ))}
        </div>
      ) : (
        <div className="text-center py-8">
          <Server size={48} className="mx-auto text-gray-300 mb-4" />
          <p className="text-gray-500">No analysis data available yet</p>
        </div>
      )}
    </div>
  );
};

// Main Protocol Viewer Component
const ProtocolViewer = ({ protocolData }) => {
  const [protocol, setProtocol] = useState(protocolData || null);
  const [activeTab, setActiveTab] = useState('fields');
  const [loading, setLoading] = useState(!protocolData);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!protocolData) {
      setLoading(true);
      fetch(`${BASE_URL}/protocol`)
        .then((response) => {
          if (!response.ok) {
            throw new Error('Failed to fetch protocol data');
          }
          return response.json();
        })
        .then((data) => {
          setProtocol(data);
          setLoading(false);
        })
        .catch((error) => {
          console.error('Error fetching protocol data:', error);
          setError(error.message || 'Failed to load protocol data');
          setLoading(false);
        });
    } else {
      setProtocol(protocolData);
    }
  }, [protocolData]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading protocol data...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="bg-red-100 text-red-600 p-4 rounded-lg mb-4">
            <p>{error}</p>
          </div>
          <p className="text-gray-600">Unable to load protocol data. Please try again later.</p>
        </div>
      </div>
    );
  }

  if (!protocol) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="bg-amber-100 text-amber-600 p-4 rounded-lg mb-4">
            <p>No protocol data available</p>
          </div>
          <p className="text-gray-600">The requested protocol information could not be found.</p>
        </div>
      </div>
    );
  }

  const { name, fields, files, dpi } = protocol;

  // Tab configuration
  const tabs = [
    { id: 'fields', label: 'Fields', icon: <Database size={18} /> },
    { id: 'files', label: 'Files', icon: <FileType size={18} /> },
    { id: 'analysis', label: 'Analysis', icon: <Eye size={18} /> },
  ];

  return (
    <div className="max-w-4xl mx-auto bg-white shadow-xl rounded-xl overflow-hidden">
      {/* Header */}
      <div className="bg-gradient-to-r from-indigo-600 to-purple-600 p-6">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-white mb-2">{name || 'Untitled Protocol'}</h1>
          <p className="text-indigo-100 text-sm">Protocol Configuration</p>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200">
        <div className="flex px-6">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center py-4 px-4 mr-4 text-sm font-medium border-b-2 transition-all duration-200 ${
                activeTab === tab.id
                  ? 'border-indigo-500 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <span className="mr-2">{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      <div className="p-6">
        {activeTab === 'fields' && (
          <div className="space-y-4">
            <div className="flex items-center mb-4">
              <Database className="text-indigo-500 mr-2" size={20} />
              <h2 className="text-xl font-semibold text-gray-800">Protocol Fields</h2>
            </div>
            
            {fields && fields.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {fields.map((field, idx) => (
                  <FieldViewer key={field._id || field.name || idx} field={field} />
                ))}
              </div>
            ) : (
              <div className="text-center py-8 bg-gray-50 rounded-lg border border-gray-200">
                <Database className="mx-auto text-gray-300 mb-4" size={48} />
                <p className="text-gray-500">No fields defined for this protocol</p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'files' && (
          <div className="space-y-4">
            <div className="flex items-center mb-4">
              <FileType className="text-indigo-500 mr-2" size={20} />
              <h2 className="text-xl font-semibold text-gray-800">Uploaded Files</h2>
            </div>
            
            <div className="bg-gray-50 rounded-lg p-4 border border-gray-200">
              {files && files.length > 0 ? (
                <div className="space-y-2">
                  {files.map((file, index) => (
                    <div
                      key={index}
                      className="flex items-center p-3 bg-white border border-gray-100 rounded-lg shadow-sm"
                    >
                      <FileType className="text-indigo-400 mr-3" size={18} />
                      <span className="text-gray-700">{file}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-6">
                  <FileType className="mx-auto text-gray-300 mb-2" size={32} />
                  <p className="text-gray-500">No files available</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'analysis' && (
          <div className="space-y-4">
            {(!dpi || (Array.isArray(dpi) && dpi.length === 0) || 
              (typeof dpi === 'object' && Object.keys(dpi).length === 0)) ? (
              <div className="text-center py-8 bg-gray-50 rounded-lg border border-gray-200">
                <Activity className="mx-auto text-gray-300 mb-4" size={48} />
                <h3 className="text-gray-600 font-medium mb-2">No Analysis Data Available</h3>
                <p className="text-gray-500 text-sm">Run the protocol to generate analysis results.</p>
              </div>
            ) : (
              <ProtocolOutputDisplay dpi={dpi} name={name} />
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ProtocolViewer;