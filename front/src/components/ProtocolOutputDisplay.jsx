import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Download, Server, ChevronLeft } from 'lucide-react';

import React from 'react';
import { Activity, Database, Code } from 'lucide-react';

const ProtocolField = ({ name, data, fields }) => {
  // Add a null/undefined check for data
  if (!data) {
    return (
      <div className="p-3 border rounded-lg bg-white shadow-sm mb-2 border-gray-100">
        <h4 className="font-medium text-gray-800 mb-2">{name || 'Unknown Field'}</h4>
        <div className="text-sm text-gray-500">No data available</div>
      </div>
    );
  }

  // Get appropriate icon based on data type
  const getFieldIcon = (value) => {
    if (typeof value === 'boolean') {
      return value ? 
        <div className="w-3 h-3 rounded-full bg-emerald-500"></div> : 
        <div className="w-3 h-3 rounded-full bg-rose-500"></div>;
    }
    if (typeof value === 'number') {
      return <Activity className="text-blue-500" size={14} />;
    }
    if (typeof value === 'string' && value.length > 20) {
      return <Code className="text-purple-500" size={14} />;
    }
    return <Database className="text-gray-400" size={14} />;
  };

  const formatValue = (value) => {
    if (value === null || value === undefined) return 'null';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'number') return value.toLocaleString();
    if (typeof value === 'string' && value.length > 50) {
      return value.substring(0, 47) + '...';
    }
    return value.toString();
  };
  
  // Group data into categories for cleaner display
  const groupData = (data) => {
    // Make sure data is an object before processing
    if (!data || typeof data !== 'object') {
      return { main: {}, metadata: {}, technical: {} };
    }
    
    if (!data.field_type) return { main: data };
    
    const result = {
      main: {},
      metadata: {},
      technical: {}
    };
    
    Object.entries(data).forEach(([key, value]) => {
      if (value === null || key === '_id') return;
      
      // Sort keys into categories
      if (['field_type', 'value', 'size', 'name', 'array_type', 'element_count'].includes(key)) {
        result.main[key] = value;
      } else if (['offset', 'bit_offset', 'timestamp'].includes(key)) {
        result.technical[key] = value;
      } else {
        result.metadata[key] = value;
      }
    });
    
    return result;
  };
  
  // Check if this is a dynamically sized field
  const isDynamicallySized = () => {
    if (!data || !data.field_type) return false;
    return data.field_type === 'dynamic array' || 
           data.is_dynamic_array === true ||
           (data.size === 0 && data.reference_field);
  };
  
  // Check if this is an array field
  const isArrayField = () => {
    if (!data || !data.field_type) return false;
    return data.field_type === 'array' || 
           data.array_type !== undefined || 
           data.element_count !== undefined;
  };
  
  // Find the reference field that determines this field's size
  const findReferencedField = () => {
    if (!isDynamicallySized()) return null;
    return data.reference_field || data.size_defining_field;
  };
  
  const referencedField = findReferencedField();
  const groupedData = groupData(data);
  
  // Add null checks before calling Object.keys
  const hasMainData = groupedData.main && Object.keys(groupedData.main).length > 0;
  const hasMetadata = groupedData.metadata && Object.keys(groupedData.metadata).length > 0;
  const hasTechnical = groupedData.technical && Object.keys(groupedData.technical).length > 0;

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
    <div className={`p-3 border rounded-lg bg-white shadow-sm mb-2 ${
      isDynamicallySized() ? 'border-indigo-200' : 
      isArrayField() ? 'border-orange-200' :
      'border-gray-100'
    }`}>
      <h4 className="font-medium text-gray-800 mb-2 flex items-center justify-between">
        <span>{name}</span>
        {isDynamicallySized() && (
          <div className="flex items-center bg-indigo-50 text-indigo-700 text-xs px-2 py-1 rounded-full">
            <span>Dynamic Size</span>
            {referencedField && (
              <span className="ml-1 font-semibold">• Size from: {referencedField}</span>
            )}
          </div>
        )}
        {isArrayField() && !isDynamicallySized() && (
          <div className="flex items-center bg-orange-50 text-orange-700 text-xs px-2 py-1 rounded-full">
            <span>Array</span>
            {data.array_type && (
              <span className="ml-1 font-semibold">• Type: {data.array_type}</span>
            )}
            {data.element_count && (
              <span className="ml-1 font-semibold">• Count: {data.element_count}</span>
            )}
          </div>
        )}
      </h4>
      
      {hasMainData && (
        <div className="mb-2">
          {Object.entries(groupedData.main).map(([key, value]) => (
            <div key={key} className="flex items-center py-1 px-2 rounded mb-1 bg-gray-50">
              <div className="flex items-center mr-2">
                {getFieldIcon(value)}
              </div>
              <span className="text-xs text-gray-500 mr-2 w-20">
                {key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}:
              </span>
              <span className="text-sm font-medium text-gray-700">
                {Array.isArray(value) ? formatArrayValue(value) : formatValue(value)}
              </span>
            </div>
          ))}
        </div>
      )}
      
      {(hasMetadata || hasTechnical) && (
        <div className="grid grid-cols-2 gap-2 mt-1">
          {Object.entries({...groupedData.metadata, ...groupedData.technical})
            .map(([key, value]) => (
              <div key={key} className="flex items-center bg-gray-50 rounded py-1 px-2">
                <span className="text-xs text-gray-500 mr-1 whitespace-nowrap overflow-hidden text-ellipsis">
                  {key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}:
                </span>
                <span className="text-xs font-medium text-gray-700 ml-auto">
                  {formatValue(value)}
                </span>
              </div>
            ))}
        </div>
      )}
    </div>
  );
};


const IPProtocolCard = ({ ip, data, onDownload }) => {
  const [isExpanded, setIsExpanded] = useState(true);
  const [currentPercentageIndex, setCurrentPercentageIndex] = useState(0);
  
  // Get percentages in descending order, ensuring 100% is first
  const percentages = Object.keys(data).sort((a, b) => {
    if (a === "100%") return -1;
    if (b === "100%") return 1;
    // Remove % and convert to number for proper numerical comparison
    return parseFloat(b) - parseFloat(a);
  });
  
  const currentPercentage = percentages[currentPercentageIndex];
  const currentData = data[currentPercentage];
  
  const goToNextPercentage = (e) => {
    if (e) e.stopPropagation(); // Prevent expansion toggle when clicked directly
    setCurrentPercentageIndex((prev) => 
      (prev + 1) % percentages.length
    );
  };
  
  const goToPrevPercentage = (e) => {
    if (e) e.stopPropagation(); // Prevent expansion toggle when clicked directly
    setCurrentPercentageIndex((prev) => 
      (prev - 1 + percentages.length) % percentages.length
    );
  };

  // Count dynamic fields with null check
  const countDynamicFields = () => {
    if (!currentData || typeof currentData !== 'object') {
      return 0;
    }
    
    return Object.values(currentData).filter(field => 
      field && (
        field.field_type === 'dynamic array' || // Changed from 'string/Code/Data'
        field.is_dynamic_array === true ||
        (field.size === 0 && field.reference_field)
      )
    ).length;
  };
  
  const dynamicFieldCount = countDynamicFields();

  return (
    <div className="bg-white rounded-lg border border-slate-200 overflow-hidden">
      <div className="border-b border-slate-200">
        <div className="flex items-center justify-between p-4">
          <div 
            className="flex items-center space-x-3 cursor-pointer flex-1"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? 
              <ChevronDown className="text-slate-400" /> : 
              <ChevronRight className="text-slate-400" />
            }
            <div className="flex items-center space-x-2">
              <Server className="text-indigo-500" size={20} />
              <span className="font-semibold text-slate-700">{ip}</span>
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
            <span className="px-2.5 py-1 bg-indigo-50 text-indigo-700 rounded-full text-xs font-medium">
              {Object.keys(currentData).length} Fields
            </span>
            {dynamicFieldCount > 0 && (
              <span className="px-2.5 py-1 bg-purple-50 text-purple-700 rounded-full text-xs font-medium">
                {dynamicFieldCount} Dynamic
              </span>
            )}
            <button
              onClick={() => onDownload(ip, currentPercentage)}
              className="flex items-center space-x-1 px-3 py-1.5 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors"
            >
              <Download size={16} />
              <span className="text-sm font-medium">Download</span>
            </button>
          </div>
        </div>
      </div>
      {isExpanded && (
        <div className="divide-y divide-slate-100">
          {Object.entries(currentData).map(([fieldName, fieldData]) => (
            <ProtocolField key={fieldName} name={fieldName} data={fieldData} />
          ))}
        </div>
      )}
    </div>
  );
};

const ProtocolOutputDisplay = ({ output, onDownload }) => {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold text-slate-800">Protocol Analysis Results</h2>
        <button
          onClick={() => onDownload('global')}
          className="flex items-center space-x-2 px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors"
        >
          <Download size={18} />
          <span>Download Global Dissector</span>
        </button>
      </div>
      <div className="grid gap-4">
        {Object.entries(output).map(([ip, data]) => (
          <IPProtocolCard 
            key={ip} 
            ip={ip} 
            data={data} 
            onDownload={onDownload}
          />
        ))}
      </div>
    </div>
  );
};

export default ProtocolOutputDisplay;