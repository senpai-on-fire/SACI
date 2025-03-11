import React from 'react';
import { Hypothesis, HypothesisId, BlueprintId } from '../types';
import { Plus, X } from 'react-feather';
import * as Select from '@radix-ui/react-select';
import { ChevronDownIcon, ChevronUpIcon } from '@radix-ui/react-icons';

// Component props
export interface HypothesisSelectorProps {
  hypotheses?: {[hypId: HypothesisId]: Hypothesis} | null;
  selected: HypothesisId | null;
  onSelection: (hypId: HypothesisId) => void;
  bpId: BlueprintId | null; // Blueprint ID for creating new hypotheses
  onAddClick: () => void; // Callback for when the add button is clicked
  isPanelOpen: boolean; // Whether the hypothesis create panel is open
}

/**
 * Hypothesis selector component that displays available hypotheses in a dropdown
 */
export const HypothesisSelector: React.FC<HypothesisSelectorProps> = ({
  hypotheses,
  selected,
  onSelection,
  bpId,
  onAddClick,
  isPanelOpen
}) => {
  const isLoading = !hypotheses;
  const selectValue = `${hypotheses ? JSON.stringify(selected) : "null"}`;

  return (
    <div className="mb-2 flex items-center">
      <label className="flex items-center space-x-2 mr-2">
        <span className="font-medium text-sm">Hypothesis:</span>
        <Select.Root
          value={selectValue}
          onValueChange={(value) => onSelection(JSON.parse(value))}
          disabled={isLoading}
        >
          <Select.Trigger 
            className="inline-flex items-center justify-between bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded py-1 pl-2 pr-2 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 min-w-[140px]"
            aria-label="Hypothesis"
          >
            <Select.Value placeholder="Select a hypothesis" />
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
                  <Select.Item value="null" className="py-1 pl-2 pr-8 text-sm outline-none cursor-default">
                    <Select.ItemText>loading...</Select.ItemText>
                  </Select.Item>
                ) : (
                  <>
                    <Select.Item 
                      value="null" 
                      className="py-1 pl-2 pr-8 text-sm outline-none data-[highlighted]:bg-indigo-100 dark:data-[highlighted]:bg-indigo-900 data-[state=checked]:font-medium cursor-default"
                    >
                      <Select.ItemText>none</Select.ItemText>
                    </Select.Item>
                    {Object.entries(hypotheses).map(([hypId, h]) => (
                      <Select.Item 
                        key={hypId} 
                        value={JSON.stringify(hypId)}
                        className="py-1 pl-2 pr-8 text-sm outline-none data-[highlighted]:bg-indigo-100 dark:data-[highlighted]:bg-indigo-900 data-[state=checked]:font-medium cursor-default"
                      >
                        <Select.ItemText>{h.name}</Select.ItemText>
                      </Select.Item>
                    ))}
                  </>
                )}
              </Select.Viewport>
              
              <Select.ScrollDownButton className="flex items-center justify-center h-6 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                <ChevronDownIcon />
              </Select.ScrollDownButton>
            </Select.Content>
          </Select.Portal>
        </Select.Root>
      </label>
      
      <button
        onClick={onAddClick}
        className={`inline-flex items-center px-2 py-1.5 border border-transparent text-xs font-medium rounded shadow-sm text-white transition-colors ${
          isPanelOpen 
            ? 'bg-gray-600 hover:bg-gray-700 focus:ring-gray-500' 
            : 'bg-indigo-600 hover:bg-indigo-700 focus:ring-indigo-500'
        }`}
        disabled={!bpId}
        title={
          !bpId 
            ? "Select a blueprint first" 
            : isPanelOpen 
              ? "Close hypothesis panel" 
              : "Create a new hypothesis"
        }
        aria-label={isPanelOpen ? "Close panel" : "Create new hypothesis"}
        focus-outline="none"
        focus-ring="2"
        focus-ring-offset="2"
      >
        {isPanelOpen ? (
          <>
            <X size={14} />
          </>
        ) : (
          <>
            <Plus size={14} />
          </>
        )}
      </button>
    </div>
  );
};