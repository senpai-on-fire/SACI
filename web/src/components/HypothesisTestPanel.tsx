import { Panel, PanelPosition } from '@xyflow/react';
import { X, RotateCcw, Trash2, ChevronDown } from 'react-feather';
import { Hypothesis, Device } from '../types';
import { useState, useEffect } from 'react';
import useSWR from 'swr';
import { fetcher, postData } from '../utils/api';
import * as Select from '@radix-ui/react-select';

interface AnalysisInfo {
  name: string;
  components_included: string[];
}

interface HypothesisTestPanelProps {
  position: PanelPosition;
  isOpen: boolean;
  onClose: () => void;
  hypothesis: Hypothesis | null;
  device: Device | null;
  bpId: string;
  onSimulationHover?: (components: string[] | null) => void;
  onLaunched: (analysisName: string, appId: number) => void;
}

interface Subsystem {
  componentIds: string[];
  simulation: string | null;
  code: string;
  isSelecting: boolean;
  startComponent: string | null;
  hoveredComponent: string | null;
}

function Log({appId}: {appId: number}) {
  let { data: logOutput } = useSWR<string>(`/api/logs?app_id=${appId}`, fetcher, {refreshInterval: 100});

  if (logOutput && logOutput.startsWith('"InternalError')) {
    logOutput = "";
  }

  return (
    <div className="px-4 pb-4 flex h-60 text-sm overflow-scroll">
      <pre>
        {logOutput}
      </pre>
    </div>
  );
}

export function HypothesisTestPanel({ isOpen, onClose, hypothesis, device, bpId, onSimulationHover, onLaunched }: HypothesisTestPanelProps) {
  const [subsystems, setSubsystems] = useState<Subsystem[]>([{
    componentIds: [],
    simulation: null,
    code: '',
    isSelecting: true,
    startComponent: null,
    hoveredComponent: null
  }]);
  const { data: analyses } = useSWR<Record<string, AnalysisInfo>>(`/api/blueprints/${bpId}/analyses`, fetcher);
  const [hoveredSimulation, setHoveredSimulation] = useState<AnalysisInfo | null>(null);
  const [isLaunching, setIsLaunching] = useState<boolean>(false);
  const [isRunning, setIsRunning] = useState<number | null>(null);

  // Clear all state when panel is closed
  useEffect(() => {
    if (!isOpen) {
      setSubsystems([{
        componentIds: [],
        simulation: '',
        code: '',
        isSelecting: true,
        startComponent: null,
        hoveredComponent: null
      }]);
      setHoveredSimulation(null);
      setIsLaunching(false);
      setIsRunning(null);
    }
  }, [isOpen]);

  // Update parent when hover state changes
  useEffect(() => {
    if (onSimulationHover) {
      onSimulationHover(hoveredSimulation?.components_included || null);
    }
  }, [hoveredSimulation, onSimulationHover]);

  if (!isOpen || !hypothesis || !device) return null;

  const getComponentName = (componentId: string) => {
    return device.components[componentId]?.name || componentId;
  };

  const handleComponentClick = (componentId: string, subsystemIndex: number) => {
    const subsystem = subsystems[subsystemIndex];
    if (!subsystem.startComponent) {
      const newSubsystems = [...subsystems];
      newSubsystems[subsystemIndex] = {
        ...subsystem,
        startComponent: componentId,
        hoveredComponent: componentId
      };
      setSubsystems(newSubsystems);
    } else {
      // Create a new subsystem with the selected range
      const startIdx = hypothesis.path.indexOf(subsystem.startComponent);
      const endIdx = hypothesis.path.indexOf(componentId);
      const [minIdx, maxIdx] = [Math.min(startIdx, endIdx), Math.max(startIdx, endIdx)];
      const componentIds = hypothesis.path.slice(minIdx, maxIdx + 1);

      const newSubsystems = [...subsystems];
      newSubsystems[subsystemIndex] = {
        ...subsystem,
        componentIds,
        isSelecting: false,
        startComponent: null,
        hoveredComponent: null
      };
      setSubsystems(newSubsystems);
    }
  };

  const handleComponentHover = (componentId: string, subsystemIndex: number) => {
    const subsystem = subsystems[subsystemIndex];
    if (subsystem.startComponent) {
      const newSubsystems = [...subsystems];
      newSubsystems[subsystemIndex] = {
        ...subsystem,
        hoveredComponent: componentId
      };
      setSubsystems(newSubsystems);
    }
  };

  const getComponentStyle = (componentId: string, subsystem: Subsystem) => {
    if (!subsystem.isSelecting) {
      const index = subsystem.componentIds.indexOf(componentId);
      if (subsystem.componentIds.length === 1) return 'rounded-full';
      if (index === 0) return 'rounded-l-full';
      if (index === subsystem.componentIds.length - 1) return 'rounded-r-full';
      return '';
    }
    
    if (!subsystem.startComponent) return '';
    
    const startIdx = hypothesis.path.indexOf(subsystem.startComponent);
    const hoverIdx = hypothesis.path.indexOf(subsystem.hoveredComponent || subsystem.startComponent);
    const currentIdx = hypothesis.path.indexOf(componentId);
    
    const [minIdx, maxIdx] = [Math.min(startIdx, hoverIdx), Math.max(startIdx, hoverIdx)];
    
    if (currentIdx >= minIdx && currentIdx <= maxIdx) {
      if (minIdx === maxIdx) return 'rounded-full';
      if (currentIdx === minIdx) return 'rounded-l-full';
      if (currentIdx === maxIdx) return 'rounded-r-full';
      return 'rounded-none';
    }
    return '';
  };

  const isComponentInRange = (componentId: string, subsystem: Subsystem) => {
    if (!subsystem.isSelecting || !subsystem.startComponent) return false;
    
    const startIdx = hypothesis.path.indexOf(subsystem.startComponent);
    const hoverIdx = hypothesis.path.indexOf(subsystem.hoveredComponent || subsystem.startComponent);
    const currentIdx = hypothesis.path.indexOf(componentId);
    
    const [minIdx, maxIdx] = [Math.min(startIdx, hoverIdx), Math.max(startIdx, hoverIdx)];
    return currentIdx >= minIdx && currentIdx <= maxIdx;
  };

  const handleReselect = (subsystemIndex: number) => {
    const newSubsystems = [...subsystems];
    newSubsystems[subsystemIndex] = {
      ...newSubsystems[subsystemIndex],
      isSelecting: true,
      startComponent: null,
      hoveredComponent: null
    };
    setSubsystems(newSubsystems);
  };

  const addSubsystem = () => {
    setSubsystems(prev => [...prev, {
      componentIds: [],
      simulation: '',
      code: '',
      isSelecting: true,
      startComponent: null,
      hoveredComponent: null
    }]);
  };

  const removeSubsystem = (index: number) => {
    setSubsystems(prev => prev.filter((_, i) => i !== index));
  };

  const isComponentUsedInOtherSubsystems = (componentId: string, currentIndex: number) => {
    return subsystems.some((subsystem, index) => 
      index !== currentIndex && subsystem.componentIds.includes(componentId)
    );
  };

  const launch = async () => {
    setIsLaunching(true);
    try {
      // TODO: change the UI to only allow selecting one simulation type for the whole system
      const simulation = subsystems[0].simulation;
      // const analysisName = analyses![simulation!].name;
      const appId = await postData<string[], number>(
        `/api/blueprints/${bpId}/analyses/${simulation}/launch`,
        subsystems.map(sub => sub.code)
      );
      // onLaunched(analysisName, appId);
      setIsRunning(appId);
    } catch (error) {
      console.error('Error launching tool', error);
      alert('Failed to launch hypothesis test. Please try again.');
    } finally {
      setIsLaunching(false);
    }
  };

  if (0) {
    onLaunched("foo", 1);
  }

  return (
    <Panel 
      className="bg-white dark:bg-neutral-900 border-2 border-indigo-600 rounded shadow-lg" 
      position="bottom-center"
      style={{ width: 'calc(100vw - 40px)', maxWidth: '900px' }}
    >
      <div className="flex flex-col">
        <div className="flex items-center justify-between p-3 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-bold">Test Hypothesis</h3>
          <button 
            onClick={onClose} 
            className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-full transition-colors"
          >
            <X size={18} className="text-gray-500" />
          </button>
        </div>
        
        {subsystems.map((subsystem, index) => (
          <div key={index} className={`p-4 ${index > 0 ? 'border-t border-gray-200 dark:border-gray-700' : ''}`}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-4">
                <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  Subsystem {index + 1}
                </h4>
                {subsystem.isSelecting ? (
                  <div className="flex gap-1">
                    {hypothesis.path.map(componentId => (
                      <button
                        key={componentId}
                        onClick={() => handleComponentClick(componentId, index)}
                        onMouseEnter={() => handleComponentHover(componentId, index)}
                        disabled={isComponentUsedInOtherSubsystems(componentId, index)}
                        className={`px-3 py-1 text-sm font-medium transition-colors
                          ${isComponentInRange(componentId, subsystem) ? 'bg-indigo-100 dark:bg-indigo-900' : 'bg-gray-100 dark:bg-gray-800'}
                          ${getComponentStyle(componentId, subsystem)}
                          hover:bg-indigo-200 dark:hover:bg-indigo-800
                          text-indigo-700 dark:text-indigo-300
                          border border-indigo-200 dark:border-indigo-700
                          disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-gray-100 dark:disabled:hover:bg-gray-800`}
                      >
                        {getComponentName(componentId)}
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <div className="flex gap-1">
                      {subsystem.componentIds.map(componentId => (
                        <span
                          key={componentId}
                          className={`px-3 py-1 text-sm font-medium
                            bg-indigo-100 dark:bg-indigo-900
                            ${getComponentStyle(componentId, subsystem)}
                            text-indigo-700 dark:text-indigo-300
                            border border-indigo-200 dark:border-indigo-700`}
                        >
                          {getComponentName(componentId)}
                        </span>
                      ))}
                    </div>
                    <button
                      onClick={() => handleReselect(index)}
                      className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-full transition-colors"
                      title="Reselect components"
                    >
                      <RotateCcw size={16} className="text-gray-500" />
                    </button>
                  </div>
                )}
              </div>
              {subsystems.length > 1 && (
                <button
                  onClick={() => removeSubsystem(index)}
                  className="p-1 hover:bg-red-100 dark:hover:bg-red-900 rounded-full transition-colors"
                  title="Remove subsystem"
                >
                  <Trash2 size={16} className="text-red-500" />
                </button>
              )}
            </div>
            <div className="space-y-4">
              <div className="flex items-center gap-4">
                <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  Simulation
                </label>
                <Select.Root
                  value={JSON.stringify(subsystem.simulation)}
                  onValueChange={(value) => {
                    const newSubsystems = [...subsystems];
                    newSubsystems[index].simulation = JSON.parse(value);
                    setSubsystems(newSubsystems);
                  }}
                >
                  <Select.Trigger 
                    className="inline-flex items-center justify-between bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded py-1 pl-2 pr-2 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 min-w-[140px]"
                    aria-label="Simulation"
                  >
                    <Select.Value placeholder="Select a simulation..." />
                    <Select.Icon className="text-gray-700 dark:text-gray-300 ml-1">
                      <ChevronDown size={16} />
                    </Select.Icon>
                  </Select.Trigger>
                  
                  <Select.Portal>
                    <Select.Content 
                      className="overflow-hidden bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded shadow-md"
                      position="popper"
                    >
                      <Select.Viewport>
                        <Select.Item 
                          value="null"
                          className="py-1 pl-2 pr-8 text-sm outline-none data-[highlighted]:bg-indigo-100 dark:data-[highlighted]:bg-indigo-900 data-[state=checked]:font-medium cursor-default"
                        >
                          <Select.ItemText>Select a simulation...</Select.ItemText>
                        </Select.Item>
                        {analyses && Object.entries(analyses).map(([id, analysis]) => (
                          <Select.Item
                            key={id}
                            value={JSON.stringify(id)}
                            className="py-1 pl-2 pr-8 text-sm outline-none data-[highlighted]:bg-indigo-100 dark:data-[highlighted]:bg-indigo-900 data-[state=checked]:font-medium cursor-default"
                            onMouseEnter={() => setHoveredSimulation(analysis)}
                            onMouseLeave={() => setHoveredSimulation(null)}
                          >
                            <Select.ItemText>{analysis.name}</Select.ItemText>
                          </Select.Item>
                        ))}
                      </Select.Viewport>
                    </Select.Content>
                  </Select.Portal>
                </Select.Root>
              </div>
              <div>
                <textarea
                  value={subsystem.code}
                  onChange={(e) => {
                    const newSubsystems = [...subsystems];
                    newSubsystems[index].code = e.target.value;
                    setSubsystems(newSubsystems);
                  }}
                  className="w-full px-2 py-1 border border-gray-300 dark:border-gray-600 rounded-md
                    bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100
                    focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                  rows={2}
                  placeholder="Enter configuration..."
                />
              </div>
            </div>
          </div>
        ))}
        <div className="px-4 pb-4 flex justify-between flex-row-reverse">
          <button
            disabled={!subsystems[0].simulation || isLaunching}
            onClick={launch}
            className="px-4 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 dark:hover:bg-indigo-800 rounded-md transition-colors disabled:bg-indigo-100 dark:disabled:bg-indigo-900 "
          >
            Launch Test
          </button>
          {subsystems.length < 2 && (
            <button
              onClick={addSubsystem}
              className="px-4 text-sm font-medium text-indigo-700 dark:text-indigo-300
                bg-indigo-100 dark:bg-indigo-900 hover:bg-indigo-200 dark:hover:bg-indigo-800
                border border-indigo-200 dark:border-indigo-700 rounded-md transition-colors"
            >
              Add Another Subsystem
            </button>
          )}
        </div>
        {isRunning !== null && (
          <Log appId={isRunning} />
        )}
      </div>
    </Panel>
  );
} 
