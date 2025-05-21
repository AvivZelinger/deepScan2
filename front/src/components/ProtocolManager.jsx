import React, { useState, useEffect } from 'react';
import { PlusCircle, FileText, ArrowLeft, Trash2 } from 'lucide-react';
import ProtocolEditor from './ProtocolEditor';
import ProtocolViewer from './ProtocolViewer';

const BASE_URL = 'http://localhost:8383';

const ProtocolManager = () => {
  const [protocols, setProtocols] = useState([]);
  const [selectedProtocol, setSelectedProtocol] = useState(null);
  const [protocolData, setProtocolData] = useState(null);
  const [isCreatingNew, setIsCreatingNew] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchProtocols();
  }, []);

  const fetchProtocols = async () => {
    try {
      const response = await fetch(`${BASE_URL}/get-names`);
      if (!response.ok) throw new Error('Failed to fetch protocols');
      const data = await response.json();
      setProtocols(data);
      setLoading(false);
    } catch (error) {
      setError('Failed to load protocols');
      setLoading(false);
    }
  };

  const fetchProtocolData = async (protocolName) => {
    try {
      const response = await fetch(`${BASE_URL}/get-protocol?name=${protocolName}`);
      if (!response.ok) throw new Error('Failed to fetch protocol data');
      const data = await response.json();
      setProtocolData(data);
      setSelectedProtocol(protocolName);
    } catch (error) {
      setError('Failed to load protocol data');
    }
  };

  const handleDeleteProtocol = async (e, protocolName) => {
    e.stopPropagation(); // Prevent triggering the parent onClick
    try {
      const confirmDelete = window.confirm(`Are you sure you want to delete the protocol "${protocolName}"?`);
      //console.log(BASE_URL+'/delete-protocol?name='+protocolName);
      if(!confirmDelete) return;
      const response = await fetch(`${BASE_URL}/delete-protocol?name=${protocolName}`, {
        method: 'DELETE',

      });
      if (!response.ok) throw new Error('Failed to delete protocol');
      // Remove the protocol from the local state
      setProtocols(protocols.filter(p => p !== protocolName));
    } catch (error) {
      setError('Failed to delete protocol');
    }
  };

  const handleProtocolSelect = (protocolName) => {
    window.history.pushState({}, '', `/protocol/${protocolName}`);
    fetchProtocolData(protocolName);
  };

  const handleBack = () => {
    window.history.pushState({}, '', '/');
    setSelectedProtocol(null);
    setProtocolData(null);
    setIsCreatingNew(false);
  };

  const handleCreateNew = () => {
    window.history.pushState({}, '', '/new');
    setIsCreatingNew(true);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-lg text-gray-600">Loading protocols...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-lg text-red-600">{error}</div>
      </div>
    );
  }

  if (isCreatingNew) {
    return (
      <div className="p-6">
        <button
          onClick={handleBack}
          className="mb-6 flex items-center text-gray-600 hover:text-gray-800 sticky top-4 bg-white z-10"
        >
          <ArrowLeft className="mr-2" size={20} />
          Back to Protocols
        </button>
        <ProtocolEditor />
      </div>
    );
  }

  if (selectedProtocol && protocolData) {
    return (
      <div className="p-6">
        <button
          onClick={handleBack}
          className="mb-6 flex items-center text-gray-600 hover:text-gray-800 sticky top-4 bg-white z-10"
        >
          <ArrowLeft className="mr-2" size={20} />
          Back to Protocols
        </button>
        <ProtocolViewer protocolData={protocolData} />
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto p-6">
      <div className="bg-white rounded-xl shadow-2xl">
        <div className="p-6 bg-gradient-to-r from-blue-500 to-purple-600 rounded-t-xl">
          <h1 className="text-3xl font-bold text-white text-center">
            Protocol Manager
          </h1>
        </div>
        
        <div className="p-6">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-xl font-semibold text-gray-800">
              Available Protocols
            </h2>
            <button
              onClick={handleCreateNew}
              className="flex items-center space-x-2 px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors"
            >
              <PlusCircle size={20} />
              <span>Create New Protocol</span>
            </button>
          </div>

          <div className="grid gap-4">
            {protocols.map((protocol) => (
              <div
                key={protocol}
                onClick={() => handleProtocolSelect(protocol)}
                className="flex items-center justify-between p-4 bg-white border border-gray-200 rounded-lg cursor-pointer hover:bg-gray-50 transition-colors"
              >
                <div className="flex items-center space-x-3">
                  <FileText className="text-blue-500" size={24} />
                  <span className="text-lg text-gray-700">{protocol}</span>
                </div>
                <button
                  onClick={(e) => handleDeleteProtocol(e, protocol)}
                  className="p-2 text-gray-500 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors"
                  title="Delete protocol"
                >
                  <Trash2 size={20} />
                </button>
              </div>
            ))}
          </div>

          {protocols.length === 0 && (
            <div className="text-center text-gray-500 mt-8">
              No protocols available. Create a new one to get started.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ProtocolManager;