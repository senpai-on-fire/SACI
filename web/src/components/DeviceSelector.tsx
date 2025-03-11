import React from 'react';
import { BlueprintId, Device } from '../types';
import * as Select from '@radix-ui/react-select';
import { ChevronDownIcon, ChevronUpIcon } from '@radix-ui/react-icons';

// Component props
export interface DeviceSelectorProps {
  devices?: {[bpId: BlueprintId]: Device}; // should be null/undefined when devices are still loading
  selected?: BlueprintId | null;
  onSelection: (bpId: BlueprintId) => void;
}

/**
 * Device selector component that displays available devices in a dropdown
 */
export const DeviceSelector: React.FC<DeviceSelectorProps> = ({
  devices,
  selected,
  onSelection
}) => {
  // Prepare options for the select element
  const isLoading = !devices;
  const selectValue = `${devices ? selected : 0}`;

  return (
    <div className="mb-2">
      <label className="flex items-center space-x-2">
        <span className="font-medium text-sm">Device:</span>
        <Select.Root
          value={selectValue}
          onValueChange={onSelection}
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
                ) : (
                  Object.entries(devices).map(([bpId, d]) => (
                    <Select.Item 
                      key={bpId} 
                      value={bpId}
                      className="py-1 pl-2 pr-8 text-sm outline-none data-[highlighted]:bg-indigo-100 dark:data-[highlighted]:bg-indigo-900 data-[state=checked]:font-medium cursor-default"
                    >
                      <Select.ItemText>{d.name}</Select.ItemText>
                    </Select.Item>
                  ))
                )}
              </Select.Viewport>
              
              <Select.ScrollDownButton className="flex items-center justify-center h-6 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                <ChevronDownIcon />
              </Select.ScrollDownButton>
            </Select.Content>
          </Select.Portal>
        </Select.Root>
      </label>
    </div>
  );
}; 