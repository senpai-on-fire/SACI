import { Panel, PanelPosition } from '@xyflow/react';
import { BlueprintId, Device, ComponentId, AnnotationId } from '../types';
import { useState } from 'react';
import { X } from 'react-feather';
import { adjacencyListOfComponentIds, groupAnnotationsByComponentId } from '../utils/helpers';
import * as Select from '@radix-ui/react-select';
import { ChevronDownIcon, ChevronUpIcon } from '@radix-ui/react-icons';

// Props for the hypothesis create panel component
interface HypothesisCreatePanelProps {
  bpId: BlueprintId | null;
  position: PanelPosition;
  isOpen: boolean;
  onClose: () => void;
  device: Device;
  onHoverComponent?: (componentId: ComponentId | null) => void;
}

// Type for annotation data with component info
interface AnnotationWithComponent {
  effect: string;
  attack_model: string;
  componentId: ComponentId;
  componentName: string;
}

// Get all relevant annotations for selected components
const getRelevantAnnotations = (device: Device, components: ComponentId[]) => {
  if (components.length === 0 || !device.annotations) return {};
  
  // Get annotations grouped by component
  const groupedAnnotations = groupAnnotationsByComponentId(device.annotations || {});
  
  // Filter annotations for selected components only
  const relevantAnnotations: {[id: AnnotationId]: AnnotationWithComponent} = {};
  
  components.forEach(compId => {
    if (groupedAnnotations[compId]) {
      Object.entries(groupedAnnotations[compId]).forEach(([annotId, annot]) => {
        relevantAnnotations[annotId] = {
          ...annot,
          componentId: compId,
          componentName: device.components[compId]?.name || compId
        };
      });
    }
  });
  
  return relevantAnnotations;
};

// The hypothesis create panel component
export function HypothesisCreatePanel({ isOpen, onClose, position, bpId, device, onHoverComponent }: HypothesisCreatePanelProps) {
  const [hypothesisName, setHypothesisName] = useState('');
  const [selectedComponents, setSelectedComponents] = useState<ComponentId[]>([]);
  const [selectedAnnotations, setSelectedAnnotations] = useState<{[id: AnnotationId]: boolean}>({});
  
  if (!isOpen || !bpId) return null;
 
  // Generate adjacency list of components
  const adjacencyList = adjacencyListOfComponentIds(device.connections);
  
  // Get all components
  const allComponents = Object.entries(device.components).map(([id, comp]) => ({
    id,
    name: comp.name || id
  }));
  
  // Handle component selection in a dropdown
  const handleComponentSelect = (index: number, compId: ComponentId) => {  
    const newSelectedComponents = compId === "none" ? 
      selectedComponents.slice(0, index) :
      [...selectedComponents.slice(0, index), compId];
    setSelectedComponents(newSelectedComponents);

    // build new selected annotations
    // the keys are the keys in relevantAnnotations
    // the values are the values in previous selectedAnnotations
    const newSelectedAnnotations = getRelevantAnnotations(device, newSelectedComponents);
    const newSelectedAnnotationsObject: {[id: AnnotationId]: boolean} = {};
    Object.keys(newSelectedAnnotations).forEach(annotId => {
      newSelectedAnnotationsObject[annotId] = selectedAnnotations[annotId] || false;
    });
    setSelectedAnnotations(newSelectedAnnotationsObject);
    return;
  };
  
  // Handle hovering over a component option in dropdown
  const handleComponentHover = (compId: ComponentId | null) => {
    console.log('hovering over component', compId);
    if (onHoverComponent) {
      onHoverComponent(compId);
    }
  };
  
  // Handle annotation selection
  const handleAnnotationSelect = (annotId: AnnotationId, selected: boolean) => {
    setSelectedAnnotations({
      ...selectedAnnotations,
      [annotId]: selected
    });
  };
  
  // Handle form submission
  const handleSubmit = () => {
    if (!hypothesisName) {
      alert('Please enter a hypothesis name');
      return;
    }
    
    // Filter selected annotations
    const finalAnnotations = Object.entries(selectedAnnotations)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    
    // TODO: Add API call to create hypothesis
    console.log('Creating hypothesis:', {
      name: hypothesisName,
      components: selectedComponents,
      annotations: finalAnnotations
    });
    
    // Clear inputs and close
    handleCancel();
  };
  
  // Function to handle cancel/close
  const handleCancel = () => {
    // Clear inputs
    setHypothesisName('');
    setSelectedComponents([]);
    setSelectedAnnotations({});
    // Close panel
    onClose();
  };

  // Render component dropdowns for path selection
  const renderComponentDropdowns = () => {
    const dropdowns = [];
    
    // First dropdown shows all components
    dropdowns.push(
      <div key="dropdown-0" className="mr-2 mb-2">
        <Select.Root
          value={selectedComponents[0] || "none"}
          onValueChange={(value) => handleComponentSelect(0, value)}
        >
          <Select.Trigger 
            className="inline-flex items-center justify-between bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded py-2 pl-3 pr-3 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 min-w-[160px]"
            aria-label="Component"
          >
            <Select.Value placeholder="Select component" />
            <Select.Icon className="text-gray-700 dark:text-gray-300 ml-2">
              <ChevronDownIcon />
            </Select.Icon>
          </Select.Trigger>
          
          <Select.Portal>
            <Select.Content 
              className="overflow-hidden bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded shadow-md z-50"
              position="popper"
            >
              <Select.ScrollUpButton className="flex items-center justify-center h-6 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                <ChevronUpIcon />
              </Select.ScrollUpButton>
              
              <Select.Viewport>
                <Select.Item 
                  value="none"
                  className="py-2 pl-3 pr-9 text-sm outline-none data-[highlighted]:bg-indigo-100 dark:data-[highlighted]:bg-indigo-900 cursor-default"
                >
                  <Select.ItemText>Select component</Select.ItemText>
                </Select.Item>
                
                {allComponents.map((comp) => (
                  <Select.Item 
                    key={comp.id} 
                    value={comp.id}
                    className="py-2 pl-3 pr-9 text-sm outline-none data-[highlighted]:bg-indigo-100 dark:data-[highlighted]:bg-indigo-900 data-[state=checked]:font-medium cursor-default"
                    onMouseEnter={() => handleComponentHover(comp.id)}
                    onMouseLeave={() => handleComponentHover(null)}
                  >
                    <Select.ItemText>{comp.name}</Select.ItemText>
                  </Select.Item>
                ))}
              </Select.Viewport>
              
              <Select.ScrollDownButton className="flex items-center justify-center h-6 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                <ChevronDownIcon />
              </Select.ScrollDownButton>
            </Select.Content>
          </Select.Portal>
        </Select.Root>
      </div>
    );
    
    // Add subsequent dropdowns based on selected components
    for (let i = 0; i < selectedComponents.length; i++) {
      // Skip the first one as it's already added
      if (i === 0) continue;
      
      const prevCompId = selectedComponents[i-1];
      const adjacentComps = adjacencyList[prevCompId] || [];
      
      // If there are no adjacent components, don't add another dropdown
      if (adjacentComps.length === 0) break;
      
      dropdowns.push(
        <div key={`dropdown-${i}`} className="mr-2 mb-2 flex items-center">
          <span className="text-gray-500 mr-2">→</span>
          <Select.Root
            value={selectedComponents[i] || "none"}
            onValueChange={(value) => handleComponentSelect(i, value)}
          >
            <Select.Trigger 
              className="inline-flex items-center justify-between bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded py-2 pl-3 pr-3 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 min-w-[160px]"
              aria-label="Component"
            >
              <Select.Value placeholder="Select component" />
              <Select.Icon className="text-gray-700 dark:text-gray-300 ml-2">
                <ChevronDownIcon />
              </Select.Icon>
            </Select.Trigger>
            
            <Select.Portal>
              <Select.Content 
                className="overflow-hidden bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded shadow-md z-50"
                position="popper"
              >
                <Select.ScrollUpButton className="flex items-center justify-center h-6 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                  <ChevronUpIcon />
                </Select.ScrollUpButton>
                
                <Select.Viewport>
                  <Select.Item 
                    value="none"
                    className="py-2 pl-3 pr-9 text-sm outline-none data-[highlighted]:bg-indigo-100 dark:data-[highlighted]:bg-indigo-900 cursor-default"
                  >
                    <Select.ItemText>Select component</Select.ItemText>
                  </Select.Item>
                  
                  {adjacentComps.map((compId) => (
                    <Select.Item 
                      key={compId} 
                      value={compId}
                      className="py-2 pl-3 pr-9 text-sm outline-none data-[highlighted]:bg-indigo-100 dark:data-[highlighted]:bg-indigo-900 data-[state=checked]:font-medium cursor-default"
                      onMouseEnter={() => handleComponentHover(compId)}
                      onMouseLeave={() => handleComponentHover(null)}
                    >
                      <Select.ItemText>{device.components[compId]?.name || compId}</Select.ItemText>
                    </Select.Item>
                  ))}
                </Select.Viewport>
                
                <Select.ScrollDownButton className="flex items-center justify-center h-6 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                  <ChevronDownIcon />
                </Select.ScrollDownButton>
              </Select.Content>
            </Select.Portal>
          </Select.Root>
        </div>
      );
    }
    
    // Add one more dropdown if there are adjacent components to the last selected component
    if (selectedComponents.length > 0) {
      const lastCompId = selectedComponents[selectedComponents.length - 1];
      const adjacentComps = adjacencyList[lastCompId] || [];
      
      if (adjacentComps.length > 0) {
        dropdowns.push(
          <div key={`dropdown-${selectedComponents.length}`} className="mr-2 mb-2 flex items-center">
            <span className="text-gray-500 mr-2">→</span>
            <Select.Root
              value="none"
              onValueChange={(value) => handleComponentSelect(selectedComponents.length, value)}
            >
              <Select.Trigger 
                className="inline-flex items-center justify-between bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded py-2 pl-3 pr-3 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 min-w-[160px]"
                aria-label="Component"
              >
                <Select.Value placeholder="Select component" />
                <Select.Icon className="text-gray-700 dark:text-gray-300 ml-2">
                  <ChevronDownIcon />
                </Select.Icon>
              </Select.Trigger>
              
              <Select.Portal>
                <Select.Content 
                  className="overflow-hidden bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded shadow-md z-50"
                  position="popper"
                >
                  <Select.ScrollUpButton className="flex items-center justify-center h-6 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                    <ChevronUpIcon />
                  </Select.ScrollUpButton>
                  
                  <Select.Viewport>
                    <Select.Item 
                      value="none"
                      className="py-2 pl-3 pr-9 text-sm outline-none data-[highlighted]:bg-indigo-100 dark:data-[highlighted]:bg-indigo-900 cursor-default"
                    >
                      <Select.ItemText>Select component</Select.ItemText>
                    </Select.Item>
                    
                    {adjacentComps.map((compId) => (
                      <Select.Item 
                        key={compId} 
                        value={compId}
                        className="py-2 pl-3 pr-9 text-sm outline-none data-[highlighted]:bg-indigo-100 dark:data-[highlighted]:bg-indigo-900 data-[state=checked]:font-medium cursor-default"
                        onMouseEnter={() => handleComponentHover(compId)}
                        onMouseLeave={() => handleComponentHover(null)}
                      >
                        <Select.ItemText>{device.components[compId]?.name || compId}</Select.ItemText>
                      </Select.Item>
                    ))}
                  </Select.Viewport>
                  
                  <Select.ScrollDownButton className="flex items-center justify-center h-6 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                    <ChevronDownIcon />
                  </Select.ScrollDownButton>
                </Select.Content>
              </Select.Portal>
            </Select.Root>
          </div>
        );
      }
    }
    
    return (
      <div className="flex flex-wrap items-center">
        {dropdowns}
      </div>
    );
  };

  const relevantAnnotations = getRelevantAnnotations(device, selectedComponents);

  return (
    <Panel 
      className="bg-white dark:bg-neutral-900 border-2 border-indigo-600 rounded shadow-lg" 
      position={position}
      style={{ width: 'calc(100vw - 40px)', maxWidth: '900px' }}
    >
      <div className="flex flex-col">
        <div className="flex items-center justify-between p-3 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-bold">Create New Hypothesis</h3>
          <button 
            onClick={handleCancel} 
            className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-full transition-colors"
          >
            <X size={18} className="text-gray-500" />
          </button>
        </div>
        
        <div className="p-4">
          {/* Hypothesis Name */}
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Hypothesis Name
            </label>
            <input
              type="text"
              value={hypothesisName}
              onChange={(e) => setHypothesisName(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white"
              placeholder="Enter hypothesis name"
            />
          </div>
          
          {/* Components Selection */}
          <div className="mb-2">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Components
            </label>
            {renderComponentDropdowns()}
          </div>
          
          {/* Annotations Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Annotations
            </label>
            <div className="border border-gray-200 dark:border-gray-700 rounded-md overflow-hidden">
              {Object.keys(relevantAnnotations).length > 0 ? (
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-800">
                    <tr>
                      <th scope="col" className="px-3 py-2 w-12"></th>
                      <th scope="col" className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Component
                      </th>
                      <th scope="col" className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Attack
                      </th>
                      <th scope="col" className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Effect
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-800">
                    {Object.entries(relevantAnnotations).map(([annotId, annot]) => (
                      <tr 
                        key={annotId}
                        className={`hover:bg-indigo-50 dark:hover:bg-indigo-900/20 transition-colors`}
                        onMouseEnter={() => handleComponentHover(annot.componentId)}
                        onMouseLeave={() => handleComponentHover(null)}
                      >
                        <td className="px-3 py-2 whitespace-nowrap">
                          <input
                            type="checkbox"
                            checked={selectedAnnotations[annotId] || false}
                            onChange={(e) => handleAnnotationSelect(annotId, e.target.checked)}
                            className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 dark:border-gray-600 rounded"
                          />
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">
                          {annot.componentName}
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">
                          {annot.attack_model || '-'}
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">
                          {annot.effect || '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="p-4 text-sm text-gray-500 dark:text-gray-400 text-center">
                  {selectedComponents.length === 0 
                    ? "Select components to view relevant annotations" 
                    : "No annotations found for selected components"}
                </div>
              )}
            </div>
          </div>
        </div>
        
        <div className="border-t border-gray-200 dark:border-gray-700 p-3 flex justify-end space-x-3">
          <button
            onClick={handleCancel}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 rounded-md"
          >
            Create
          </button>
        </div>
      </div>
    </Panel>
  );
}