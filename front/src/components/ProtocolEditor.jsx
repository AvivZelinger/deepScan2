import React, { useState, useEffect } from 'react';
import {
  PlusIcon,
  TrashIcon,
  UploadIcon,
  SaveIcon,
  DownloadIcon,
  PlayIcon,
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  Server,
  Puzzle,
} from 'lucide-react';
import FieldEditor from './FieldEditor';
import CustomTypesManager from './CustomTypesManager';

const DEFAULT_FIELD = { name: '', size: '4', type: 'int', referenceField: '' };
const BASE_URL = 'http://localhost:8383';

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

// IP Protocol Card Component
const IPProtocolCard = ({ ip, data, onDownload }) => {
  const [isExpanded, setIsExpanded] = React.useState(true);
  const [currentPercentageIndex, setCurrentPercentageIndex] = React.useState(0);
  
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

  // Count dynamic fields with null check
  const countDynamicFields = () => {
    if (!currentData || typeof currentData !== 'object') {
      return 0;
    }
    
    return Object.values(currentData).filter(field => 
      field && (
        field.field_type === 'dynamic array' ||
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
              <DownloadIcon size={16} />
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

// Protocol Output Display Component
const ProtocolOutputDisplay = ({ output, onDownload }) => {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold text-slate-800">Protocol Analysis Results</h2>
        <button
          onClick={() => onDownload('global')}
          className="flex items-center space-x-2 px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors"
        >
          <DownloadIcon size={18} />
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

// Main Protocol Editor Component
const ProtocolEditor = () => {
  const [protocolName, setProtocolName] = useState('');
  const [fields, setFields] = useState([DEFAULT_FIELD]);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [output, setOutput] = useState({});
  const [loading, setLoading] = useState(false);
  const [pcapUploaded, setPcapUploaded] = useState(false);
  const [protocolRuned, setProtocolRuned] = useState(false);
  const [isCustomTypesModalOpen, setIsCustomTypesModalOpen] = useState(false);
  const [customTypes, setCustomTypes] = useState([]);

  const isDissectorReady = pcapUploaded && protocolRuned;
  const canSave = isDissectorReady && Object.keys(output).length > 0 && protocolName.trim() !== '';

  // Fetch custom types on mount
  useEffect(() => {
    fetchCustomTypes();
  }, []);

  const fetchCustomTypes = async () => {
    try {
      const response = await fetch(`${BASE_URL}/custom-types`);
      if (response.ok) {
        const data = await response.json();
        setCustomTypes(data);
      } else {
        console.error("Failed to fetch custom types:", response.status);
      }
    } catch (error) {
      console.error('Error fetching custom types:', error);
    }
  };

  const handleCustomTypeSelect = (type) => {
    // Add a new field with the selected custom type
    const typeName = `custom:${type.name}`;
    
    const size = calculateCustomTypeSize(type).toString();
    
    setFields([
      ...fields,
      { 
        name: '', 
        type: typeName,
        size: size,
        customTypeName: type.name,
        referenceField: ''
      }
    ]);
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

  const handleFieldChange = (index, fieldKey, value) => {
    setFields((prevFields) =>
      prevFields.map((f, i) =>
        i === index ? { ...f, [fieldKey]: value } : f
      )
    );
  };

  const addField = () => {
    setFields((prevFields) => [...prevFields, { ...DEFAULT_FIELD }]);
  };

  const removeField = (index) => {
    setFields((prevFields) => prevFields.filter((_, i) => i !== index));
  };

  const validateFields = () => {
    if (protocolName.trim() === '') {
      alert('Protocol name is required');
      return false;
    }

    for (let i = 0; i < fields.length; i++) {
      const field = fields[i];
      
      if (field.name.trim() === '') {
        alert(`Field ${i + 1} requires a name`);
        return false;
      }

      if (field.type === 'dynamic array') {
        if (!field.referenceField) {
          alert(`Dynamic array field "${field.name}" requires a length field`);
          return false;
        }
        
        // Verify the referenced field exists
        const refFieldIndex = fields.findIndex(f => f.name === field.referenceField);
        if (refFieldIndex === -1) {
          alert(`Length field for "${field.name}" does not exist`);
          return false;
        }
      }

      if (field.type === 'array') {
        if (!field.arrayType || !field.arrayCount || parseInt(field.arrayCount) <= 0) {
          alert(`Array field "${field.name}" requires a valid element type and count`);
          return false;
        }
      }

      if ((field.type === 'custom' || field.type === 'bitfield') && 
          (!field.size || isNaN(parseInt(field.size)) || parseInt(field.size) <= 0)) {
        alert(`${field.type === 'custom' ? 'Custom' : 'Bitfield'} field "${field.name}" requires a valid size`);
        return false;
      }
    }

    return true;
  };

  const handleFileChange = (event) => {
    setSelectedFiles(Array.from(event.target.files));
  };

  const uploadFiles = async () => {
    if (!selectedFiles.length) {
      alert('Please select at least one PCAP file before uploading.');
      return;
    }

    setLoading(true);
    const formData = new FormData();
    selectedFiles.forEach((file) => {
      formData.append('pcapFile', file);
    });

    try {
      const response = await fetch(`${BASE_URL}/upload`, {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        alert('PCAP files uploaded successfully.');
        setPcapUploaded(true);
      } else {
        alert('Failed to upload PCAP files. Please check the server.');
      }
    } catch (error) {
      console.error('Error uploading PCAP files:', error);
      alert('An error occurred while uploading the PCAP files.');
    } finally {
      setLoading(false);
    }
  };

  const handleRun = async () => {
    if (!validateFields()) {
      return;
    }

    // Format fields based on their type with custom type handling
    const formattedFields = fields.map((field) => {
      const { name, size, type, referenceField, arrayType, arrayCount } = field;
      
      // Handle different field types with specific formatting
      if (type === 'dynamic array') {
        return `${name} 0 char ${referenceField}`;
      }
      
      if (type === 'array') {
        const newarrayType= arrayType.replace('custom:', '');
        console.log(`${name} ${size} array ${newarrayType} ${arrayCount}`)
        return `${name} ${size} array ${newarrayType} ${arrayCount}`;
      }
      
      // Handle custom types
      if (type.startsWith('custom:')) {
        const customTypeName = type.replace('custom:', '');
        return `${name} ${size} ${customTypeName}`;
      }
      
      // Default format for other field types
      return `${name} ${size} ${type}`;
    });

    const fileContent = [
      protocolName,
      fields.length,
      ...formattedFields
    ].join('\n');

    setLoading(true);

    try {
      const response = await fetch(`${BASE_URL}/data`, {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
        },
        body: fileContent,
      });

      if (response.ok) {
        alert('Protocol run and command executed successfully.');
        setProtocolRuned(true);
      } else {
        alert('Failed to run protocol. Please check the server.');
      }
    } catch (error) {
      console.error('Error running protocol:', error);
      alert('Failed to run protocol. Please check the server.');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    if (!canSave) {
      alert('Please ensure protocol is run and output is available before saving.');
      return;
    }

    const protocolData = {
      name: protocolName,
      fields: fields,
      files: selectedFiles.map(file => file.name),
      dpi: output,
    };

    try {
      const response = await fetch(`${BASE_URL}/save-protocol`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(protocolData),
      });

      if (response.ok) {
        alert('Protocol configuration saved successfully.');
      } else {
        alert('Failed to save protocol configuration.');
      }
    } catch (error) {
      console.error('Error saving protocol:', error);
      alert('An error occurred while saving the protocol configuration.');
    }
  };

  const downloadDissectorForIP = (ip, percentage = "100%") => {
    const encodedIP = encodeURIComponent(ip);
    const encodedPercentage = encodeURIComponent(percentage);
    window.open(`${BASE_URL}/download-dissector?ip=${encodedIP}&protocol=${protocolName}&percentage=${encodedPercentage}`, '_blank');
  };

  const downloadDissectorGlobal = () => {
    window.open(`${BASE_URL}/download-dissector?ip=Global&protocol=${protocolName}`, '_blank');
  };

  const fetchOutput = async () => {
    try {
      const response = await fetch(`${BASE_URL}/output`);
      if (!response.ok) throw new Error('Failed to fetch output');
      const data = await response.json();
      
      // Process data based on its structure
      if (data.dpi) {
        // If data has a "dpi" property (like in the paste.txt format)
        setOutput(data.dpi);
      } else if (data.protocol) {
        // Format from the JSON file with a "protocol" key
        setOutput(data.dpi || {});
      } else {
        // If data is already in the expected format
        setOutput(data);
      }
    } catch (error) {
      console.error('Error fetching output:', error);
      setOutput({ error: 'Unable to retrieve output. Please try again.' });
    }
  };

  useEffect(() => {
    if (protocolRuned) {
      fetchOutput();
      const intervalId = setInterval(fetchOutput, 5000);
      return () => clearInterval(intervalId);
    }
  }, [protocolRuned]);

  return (
    <div className="max-w-4xl mx-auto p-6 bg-white shadow-2xl rounded-xl">
      <div className="mb-6 bg-gradient-to-r from-blue-500 to-purple-600 p-4 rounded-lg">
        <h1 className="text-3xl font-bold text-white text-center">
          Protocol Configuration
        </h1>
      </div>

      <div className="space-y-6">
        {/* Protocol Name Field */}
        <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-md">
          <h2 className="text-xl font-semibold mb-4 text-gray-800">
            Protocol Name
          </h2>
          <input
            type="text"
            value={protocolName}
            onChange={(e) => setProtocolName(e.target.value)}
            placeholder="Enter protocol name"
            className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
        </div>

        {/* Define Protocol Fields Section */}
        <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-md">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-semibold text-gray-800 flex items-center">
              <span>Define Protocol Fields</span>
              {customTypes.length > 0 && (
                <span className="ml-3 px-2 py-1 bg-indigo-100 text-indigo-700 text-xs rounded-full">
                  {customTypes.length} Custom Types Available
                </span>
              )}
            </h2>
            
            {/* Custom Types Manager Button */}
            <button
              onClick={() => setIsCustomTypesModalOpen(true)}
              className="flex items-center space-x-2 px-3 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors"
              title="Define custom structure types"
            >
              <Puzzle size={18} />
              <span>Manage Custom Types</span>
            </button>
          </div>
          
          {fields.map((field, index) => (
            <FieldEditor
              key={index}
              field={field}
              fields={fields}
              index={index}
              customTypes={customTypes}
              onFieldChange={(fieldKey, value) =>
                handleFieldChange(index, fieldKey, value)
              }
              onRemove={() => removeField(index)}
            />
          ))}
          <div className="flex space-x-3 mt-4">
            <button
              onClick={addField}
              className="flex items-center space-x-2 bg-green-500 text-white px-4 py-2 rounded-md hover:bg-green-600 transition-colors"
            >
              <PlusIcon size={20} />
              <span>Add Field</span>
            </button>
          </div>
        </div>

        {/* File Upload Section */}
        <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-md">
          <h2 className="text-xl font-semibold mb-4 text-gray-800">
            File Upload
          </h2>
          <div className="flex flex-col md:flex-row items-center space-y-4 md:space-y-0 md:space-x-4">
            <input
              type="file"
              accept=".pcap,.pcapng"
              onChange={handleFileChange}
              multiple
              className="block w-full text-sm text-gray-500
                         file:mr-4 file:py-2 file:px-4
                         file:rounded-full file:border-0
                         file:text-sm file:font-semibold
                         file:bg-blue-50 file:text-blue-700
                         hover:file:bg-blue-100"
            />
            <button
              onClick={uploadFiles}
              disabled={loading}
              className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors ${
                loading
                  ? 'bg-gray-400 cursor-not-allowed'
                  : 'bg-blue-500 text-white hover:bg-blue-600'
              }`}
            >
              <UploadIcon size={20} />
              <span>{loading ? 'Uploading...' : 'Upload'}</span>
            </button>
          </div>
        </div>

        {/* Server Output Section */}
        <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-md">
          <div className="bg-white rounded-lg">
            {output.error ? (
              <div className="text-rose-500 mt-2">{output.error}</div>
            ) : Object.keys(output).length === 0 ? (
              <div className="text-slate-500 mt-2">No output available</div>
            ) : (
              <ProtocolOutputDisplay 
                output={output} 
                onDownload={(ip, percentage) => {
                  if (ip === 'global') {
                    downloadDissectorGlobal();
                  } else {
                    downloadDissectorForIP(ip, percentage);
                  }
                }} 
              />
            )}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex justify-center space-x-4 mt-6">
          <button
            onClick={handleRun}
            disabled={loading}
            className={`flex items-center space-x-2 px-6 py-3 rounded-lg text-white font-bold transition-colors ${
              loading
                ? 'bg-gray-400 cursor-not-allowed'
                : 'bg-purple-600 hover:bg-purple-700'
            }`}
          >
            <PlayIcon size={24} />
            <span>{loading ? 'Running...' : 'Run'}</span>
          </button>

          <button
            onClick={handleSave}
            disabled={!canSave}
            className={`flex items-center space-x-2 px-6 py-3 rounded-lg text-white font-bold transition-colors ${
              !canSave
                ? 'bg-gray-400 cursor-not-allowed'
                : 'bg-green-600 hover:bg-green-700'
            }`}
          >
            <SaveIcon size={24} />
            <span>Save</span>
          </button>
        </div>
      </div>

      {/* Custom Types Manager Modal */}
      <CustomTypesManager
        isOpen={isCustomTypesModalOpen}
        onClose={() => {
          setIsCustomTypesModalOpen(false);
          fetchCustomTypes(); // Refresh types when modal is closed
        }}
        onTypeSelect={handleCustomTypeSelect}
        existingTypes={customTypes}
      />
    </div>
  );
};

export default ProtocolEditor;