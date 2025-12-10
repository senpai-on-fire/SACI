import React, { useRef, useState } from 'react';
import { BlueprintId, Device } from '../types';
import * as Select from '@radix-ui/react-select';
import { ChevronDownIcon, ChevronUpIcon } from '@radix-ui/react-icons';
import { useSWRConfig } from 'swr';
import { postData } from '../utils/api';

// Component props
export interface DeviceSelectorProps {
  devices?: {[bpId: BlueprintId]: Device}; // should be null/undefined when devices are still loading
  selected?: BlueprintId | null;
  onSelection: (bpId: BlueprintId) => void;
  onDeviceChange?: () => void; // Callback to reset hypothesis selection
}

/**
 * Device selector component that displays available devices in a dropdown
 */
export const DeviceSelector: React.FC<DeviceSelectorProps> = ({
  devices,
  selected,
  onSelection,
  onDeviceChange
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { mutate } = useSWRConfig();
  const [isUploading, setIsUploading] = useState(false);
  
  // Prepare options for the select element
  const isLoading = !devices;
  const selectValue = `${devices ? selected : 0}`;

  const handleSelection = (bpId: BlueprintId) => {
    onSelection(bpId);
    if (onDeviceChange) {
      onDeviceChange();
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    try {
      const fileContent = await file.text();
      const blueprintData = JSON.parse(fileContent);
      
      if (!blueprintData.id) {
        alert('Invalid blueprint file: missing "id" field');
        return;
      }

      // Upload the blueprint using the API
      await postData(`/api/blueprints/${blueprintData.id}`, blueprintData);
      
      // Refresh the blueprints list
      await mutate('/api/blueprints');
      
      // Select the newly uploaded blueprint
      onSelection(blueprintData.id);
      if (onDeviceChange) {
        onDeviceChange();
      }
      
      // Reset file input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      
    } catch (error) {
      console.error('Error uploading blueprint:', error);
      if (error instanceof SyntaxError) {
        alert('Invalid JSON file. Please check the file format.');
      } else {
        alert('Failed to upload blueprint. Please try again.');
      }
    } finally {
      setIsUploading(false);
    }
  };

  const handleUploadClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="mb-2 flex items-center space-x-3">
      <label className="flex items-center space-x-2">
        <span className="font-medium text-sm">Device:</span>
        <Select.Root
          value={selectValue}
          onValueChange={handleSelection}
          disabled={isLoading}
        >
          <Select.Trigger 
            className="inline-flex items-center justify-between bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded py-1 pl-2 pr-2 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 min-w-[140px]"
            aria-label="Device"
          >
            <Select.Value placeholder="Select a device" />
            <Select.Icon className="text-gray-700 dark:text-gray-300 ml-1">
              <ChevronDownIcon />
            </Select.Icon>
          </Select.Trigger>
          
          <Select.Portal>
            <Select.Content 
              className="overflow-hidden bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded shadow-md"
              position="popper"
            >
              <Select.ScrollUpButton className="flex items-center justify-center h-6 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                <ChevronUpIcon />
              </Select.ScrollUpButton>
              
              <Select.Viewport>
                {isLoading ? (
                  <Select.Item value="0" className="py-1 pl-2 pr-8 text-sm outline-none cursor-default">
                    <Select.ItemText>loading...</Select.ItemText>
                  </Select.Item>
                ) : devices ? (
                  Object.entries(devices).map(([bpId, d]) => (
                    <Select.Item 
                      key={bpId} 
                      value={bpId}
                      className="py-1 pl-2 pr-8 text-sm outline-none data-[highlighted]:bg-indigo-100 dark:data-[highlighted]:bg-indigo-900 data-[state=checked]:font-medium cursor-default"
                    >
                      <Select.ItemText>{d.name}</Select.ItemText>
                    </Select.Item>
                  ))
                ) : (
                  <Select.Item value="0" className="py-1 pl-2 pr-8 text-sm outline-none cursor-default">
                    <Select.ItemText>No devices available</Select.ItemText>
                  </Select.Item>
                )}
              </Select.Viewport>
              
              <Select.ScrollDownButton className="flex items-center justify-center h-6 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                <ChevronDownIcon />
              </Select.ScrollDownButton>
            </Select.Content>
          </Select.Portal>
        </Select.Root>
      </label>
      
      {/* Upload Blueprint Button */}
      <button
        onClick={handleUploadClick}
        className="px-3 py-1 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 rounded disabled:bg-indigo-400 transition-colors"
        disabled={isLoading || isUploading}
        title="Upload Blueprint JSON file"
      >
        {isUploading ? 'Uploading...' : 'Upload Blueprint'}
      </button>
      
      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".json"
        onChange={handleFileUpload}
        className="hidden"
      />
    </div>
  );
}; 