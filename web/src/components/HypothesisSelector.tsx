import React from 'react';
import { Hypothesis, HypothesisId } from '../types';

// Component props
export interface HypothesisSelectorProps {
  hypotheses?: {[hypId: HypothesisId]: Hypothesis} | null;
  selected: HypothesisId | null;
  onSelection: (hypId: HypothesisId) => void;
}

/**
 * Hypothesis selector component that displays available hypotheses in a dropdown
 */
export const HypothesisSelector: React.FC<HypothesisSelectorProps> = ({
  hypotheses,
  selected,
  onSelection
}) => {
  // Prepare options for the select element
  const options = hypotheses ?
    [<option key="null" value="null">none</option>].concat(
      Object.entries(hypotheses).map(([hypId, h]) =>
        <option key={hypId} value={JSON.stringify(hypId)}>{h.name}</option>
      )
    ) :
    [<option key="null" value="null">loading...</option>];

  return (
    <div className="mb-2">
      <label className="flex items-center space-x-2">
        <span className="font-medium text-sm">Hypothesis:</span>
        <div className="relative">
          <select
            className="appearance-none bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded py-1 pl-2 pr-8 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
            value={`${hypotheses ? JSON.stringify(selected) : null}`}
            onChange={e => onSelection(JSON.parse(e.target.value))}
            disabled={!hypotheses}
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