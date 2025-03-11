import React from 'react';
import { BlueprintId, Device } from '../types';

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
  const options = devices ?
    Object.entries(devices).map(([bpId, d]) => <option key={bpId} value={bpId}>{d.name}</option>) :
    [<option key="loading" value="0">loading...</option>];

  return (
    <div className="mb-2">
      <label className="flex items-center space-x-2">
        <span className="font-medium text-sm">Device:</span>
        <div className="relative">
          <select
            className="appearance-none bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded py-1 pl-2 pr-8 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
            value={`${devices ? selected : 0}`}
            onChange={e => onSelection(e.target.value)}
            disabled={!devices}
          >
            {options}
          </select>
          <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-700 dark:text-gray-300">
            <svg className="fill-current h-4 w-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
              <path d="M9.293 12.95l.707.707L15.657 8l-1.414-1.414L10 10.828 5.757 6.586 4.343 8z" />
            </svg>
          </div>
        </div>
      </label>
    </div>
  );
}; 