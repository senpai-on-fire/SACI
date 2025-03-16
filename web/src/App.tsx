import { Panel } from '@xyflow/react';
import { useEffect, useState } from 'react';
import { Maximize2, Minimize2 } from 'react-feather';
import { VncScreen } from 'react-vnc';
import useSWR from 'swr';
import {
  ActiveCPV,
  CPVsPanel,
  DeviceSelector,
  Flow,
  HypothesisCreatePanel,
  HypothesisSelector,
  HypothesisTestPanel
} from './components';
import {
  BlueprintId,
  Component,
  ComponentId,
  Device,
  Hypothesis,
  HypothesisId
} from './types';
import { fetcher } from './utils/api';

import '@xyflow/react/dist/style.css';
import './App.css';

type AnalysisId = string;
type AnalysisInfo = {
  name: string,
  components_included: ComponentId[],
};
type AnalysisLauncherProps = {
  bpId: BlueprintId,
  analysisId: AnalysisId,
  analysisInfo: AnalysisInfo,
  onLaunch: (app: number) => void,
  onHover?: () => void,
  onUnhover?: () => void,
};
function AnalysisLauncher({bpId, analysisId, analysisInfo, onLaunch, onHover, onUnhover}: AnalysisLauncherProps) {
  type LaunchStatus =
    "unlaunched" |
    "launching" |
    "launched" |
    "error";
  const [launchStatus, setLaunchStatus] = useState<LaunchStatus>("unlaunched");
  const launchAnalysis = async () => {
    console.log(`launching analysis ${analysisId}`);
    setLaunchStatus("launching");
    const resp = await fetch(
      `/api/blueprints/${bpId}/analyses/${analysisId}/launch`,
      {method: "POST"},
    );
    if (!resp.ok) {
      console.log("failed to launch analysis");
      setLaunchStatus("error");
      const errResp = await resp.json();
      console.log(`error details: ${JSON.stringify(errResp)}`);
    } else {
      const app = await resp.json();
      setLaunchStatus("unlaunched");
      onLaunch(app);
    }
  };

  let icon;
  switch (launchStatus) {
  case "unlaunched":
    icon = "▶";
    break;
  case "launching":
    icon = <div className="inline-block h-4 w-4 \
             animate-spin rounded-full \
             border-4 border-solid border-current border-e-transparent \
             align-[-0.125em] text-surface dark:text-white">
           </div>;
    break;
  case "launched":
    icon = "✓";
    break;
  case "error":
    icon = "✕";
    break;
  }

  return (
    <button
      className="px-3 py-1 \
        bg-indigo-500 hover:bg-indigo-600 active:bg-indigo-700 \
        disabled:bg-indigo-200 disabled:hover:border-transparent
        text-white"
      onClick={launchAnalysis}
      onMouseEnter={() => onHover ? onHover() : undefined}
      onMouseLeave={() => onUnhover ? onUnhover() : undefined}
      disabled={launchStatus !== "unlaunched"} >
      {analysisInfo.name} {icon}
    </button>
  );
}

type AnalysesProps = {
  bpId: BlueprintId,
  analysisFilter?: (analysisInfo: AnalysisInfo) => boolean,
  onAnalysisLaunch: (analysisInfo: AnalysisInfo, app: number) => void,
  onAnalysisHover?: (analysisInfo: AnalysisInfo) => void,
  onAnalysisUnhover?: () => void,
};
function Analyses({bpId, analysisFilter, onAnalysisLaunch, onAnalysisHover, onAnalysisUnhover}: AnalysesProps) {
  // TODO: replace deviceIdx with a blueprint ID. for now it doesn't matter anyway
  const { data, error, isLoading } = useSWR(`/api/blueprints/${bpId}/analyses`, fetcher);

  if (error) {
    return <div>Error loading analyses: {error}</div>;
  } else if (isLoading) {
    return <div>Loading analyses...</div>;
  } else {
    const analyses = Object.entries(data as {[name: string]: AnalysisInfo}).flatMap(([id, analysisInfo]) =>
      !analysisFilter || analysisFilter(analysisInfo) ?
        [<li className="m-1" key={id}>
           <AnalysisLauncher
             bpId="foo"
             analysisId={id}
             analysisInfo={analysisInfo as AnalysisInfo}
             onLaunch={app => onAnalysisLaunch(analysisInfo as AnalysisInfo, app)}
             onHover={() => onAnalysisHover ? onAnalysisHover(analysisInfo as AnalysisInfo) : undefined}
             onUnhover={onAnalysisUnhover} />
         </li>] :
        []
    );
    return (
      <div>
        <h3 className="text-2xl font-bold pl-1 pb-2">Analyses</h3>
        <ul>
          {analyses}
        </ul>
      </div>
    );
  }
}

type ComponentPanelProps = {
  componentId: ComponentId,
  component: Component,
} & AnalysesProps;
function ComponentPanel({componentId, component, analysisFilter, ...analysesProps}: ComponentPanelProps) {
  const parameters = Object.entries(component.parameters ?? {}).map(([id, val]) =>
    <li key={id}>{id}: {val}</li>
  );
  return (
    <>
      <h3 className="text-2xl font-bold">Component: {component.name}</h3>
      <ul>
        {parameters}
      </ul>
        <Analyses
          analysisFilter={info => info.components_included.includes(componentId) && (!analysisFilter || analysisFilter(info))}
          {...analysesProps} />
    </>
  );
}

type AnalysisPanelProps = {
  name: string,
  app: number,
  onClose: () => void,
};
function AnalysisPanel({name, app, onClose}: AnalysisPanelProps) {
  // TODO: fix this hacky width/height calc somehow?
  return <Panel className="flex flex-col border-2 border-indigo-600 rounded bg-white dark:bg-neutral-900" style={{width: "calc(100vw - 30px)", height: "calc(100vh - 30px)"}} position="top-left">
    <div className="flex-none text-xl"><button onClick={onClose}>✕</button>{name}</div>
    <VncScreen className="flex-1" url={`/api/vnc?app_id=${app}`} scaleViewport />
  </Panel>;
}

type HypothesisPanelProps = {
  device: Device,
  hypothesis: Hypothesis,
} & AnalysesProps;
function HypothesisPanel({bpId, device, hypothesis, ...analysesProps}: HypothesisPanelProps) {
  return <>
    <h3 className="text-2xl font-bold">Hypothesis: {hypothesis.name}</h3>
    {hypothesis.path.length > 0 ?
      <div>Entry: {device.components[hypothesis.path[0]].name}</div> :
      <> </>}
    {hypothesis.path.length > 0 ?
      <div>Exit: {device.components[hypothesis.path[hypothesis.path.length-1]].name}</div> :
      <> </>}
    <Analyses bpId={bpId} {...analysesProps} />
  </>;
}

function App() {
  const { data: devices } = useSWR("/api/blueprints", fetcher);

  const [bpId, setBpId] = useState<BlueprintId | null>(null);
  // TODO: is there a less janky way to have this "default"?
  useEffect(() => {
    const bpIds = devices ? Object.keys(devices) : [];
    if (!bpId && bpIds.length > 0) {
      setBpId(bpIds[0]);
    }
  }, [devices, bpId]);
  const device = devices && bpId ? devices[bpId] : null;

  const [hypId, setHypId] = useState<HypothesisId | null>(null);
  const hypothesis = device && hypId ? device.hypotheses?.[hypId] : null;

  const [hoveringAnalysis, setHoveringAnalysis] = useState<AnalysisInfo | null>(null);
  const [hoveredComponents, setHoveredComponents] = useState<ComponentId[] | null>(null);

  const handleSimulationHover = (components: ComponentId[] | null) => {
    setHoveredComponents(components);
  };

  const [selectedComponent, setSelectedComponent] = useState<ComponentId | null>(null);
  
  const [showHypothesisCreatePanel, setShowHypothesisCreatePanel] = useState(false);
  const [showHypothesisTestPanel, setShowHypothesisTestPanel] = useState(false);
  const [importedCPVData, setImportedCPVData] = useState<{name: string, path: ComponentId[]} | null>(null);

  // Update handlers to close activeCPV when panels are opened
  const handleCreatePanelOpen = (open: boolean) => {
    setShowHypothesisCreatePanel(open);
    if (open) {
      setActiveCPV(undefined);
    }
  };

  const handleTestPanelOpen = (open: boolean) => {
    setShowHypothesisTestPanel(open);
    if (open) {
      setActiveCPV(undefined);
    }
  };

  type RunningAnalysis = {name: string, app: number};
  const [showingAnalysis, setShowingAnalysis] = useState<RunningAnalysis | null>(null);

  // Add panel minimization state
  const [panelMinimized, setPanelMinimized] = useState(true);

  // Add activeCPV state
  const [activeCPV, setActiveCPV] = useState<ActiveCPV>(undefined);
  
  // Add hoveredComponent state for highlighting in Flow
  const [hoveredComponent, setHoveredComponent] = useState<ComponentId | null>(null);

  // Handle importing CPV data
  const handleImportCPV = (name: string, path: ComponentId[]) => {
    setImportedCPVData({ name, path });
    setShowHypothesisCreatePanel(true);
  };

  const handleDeviceChange = (newBpId: BlueprintId) => {
    setBpId(newBpId);
    setHypId(null);
    setShowHypothesisTestPanel(false);
  };

  let panelInner = null;
  if (bpId && device) {
    const analysesProps: AnalysesProps = {
      bpId,
      onAnalysisLaunch: (analysis, app) => setShowingAnalysis({name: analysis.name, app}),
      onAnalysisHover: setHoveringAnalysis,
      onAnalysisUnhover: () => setHoveringAnalysis(null),
    };
    if (selectedComponent) {
      panelInner =
        <ComponentPanel
          componentId={selectedComponent}
          component={device.components[selectedComponent]}
          {...analysesProps} />;
    } else if (hypothesis) {
      panelInner = 
        <HypothesisPanel
          device={device}
          hypothesis={hypothesis}
          {...analysesProps} />;
    } else {
      panelInner = <Analyses {...analysesProps} />;
    }
  }

  const highlights = {
    entry: hypothesis?.path[0],
    exit: hypothesis?.path[hypothesis?.path.length - 1],
    involved: hoveredComponents || hoveringAnalysis?.components_included,
    activePath: activeCPV?.path,
    hoveredComponent: hoveredComponent,
    hypothesisPath: hypothesis?.path,
  };

  return (
    <>
      <div style={{ width: '100vw', height: '100vh'}}>
        <Flow
          bpId={bpId}
          device={device}
          highlights={highlights}
          onComponentClick={setSelectedComponent}
          onPaneClick={() => setSelectedComponent(null)} >
          <Panel className="p-4" position="top-left">
            <div className="flex items-start">
              <h1 className="font-bold mr-6 mt-1">SACI</h1>
              <div className="flex flex-col">
                <DeviceSelector 
                  devices={devices} 
                  selected={bpId} 
                  onSelection={handleDeviceChange}
                />
                <HypothesisSelector 
                  hypotheses={device?.hypotheses} 
                  selected={hypId} 
                  onSelection={setHypId} 
                  bpId={bpId}
                  onAddClick={() => handleCreatePanelOpen(!showHypothesisCreatePanel)}
                  isCreatePanelOpen={showHypothesisCreatePanel}
                  onTestClick={() => handleTestPanelOpen(!showHypothesisTestPanel)}
                  isTestPanelOpen={showHypothesisTestPanel}
                />
              </div>
            </div>
          </Panel>
          {panelInner ? (
            <Panel 
              className="bg-white dark:bg-neutral-900 border-2 p-4 border-indigo-600 rounded overflow-hidden" 
              position="bottom-left"
              style={{
                maxHeight: panelMinimized ? 'auto' : '400px',
                maxWidth: 'md',
                transition: 'all 0.3s ease'
              }}
            >
              <div className="float-right cursor-pointer"
                  onClick={() => setPanelMinimized(!panelMinimized)}>
                {panelMinimized ? 
                  <Maximize2 className="text-indigo-600 ml-auto" size={20} /> : 
                  <Minimize2 className="text-indigo-600 ml-auto" size={20} />
                }
              </div>
              {!panelMinimized && (
                <div className="max-h-80 overflow-auto">
                  {panelInner}
                </div>
              )}
            </Panel>
          ) : (
            <> </>
          )}
          {showingAnalysis ?
            <AnalysisPanel name={showingAnalysis.name} app={showingAnalysis.app} onClose={() => setShowingAnalysis(null)} /> :
            <> </>}
          <CPVsPanel 
            bpId={bpId} 
            device={device} 
            position="top-right" 
            activeCPV={activeCPV}
            onActiveCPVChange={setActiveCPV}
            onImportCPV={handleImportCPV}
          />
          <HypothesisCreatePanel
            bpId={bpId}
            position="bottom-center"
            isOpen={showHypothesisCreatePanel}
            onClose={() => {
              handleCreatePanelOpen(false);
              setImportedCPVData(null);
            }}
            device={device}
            onHoverComponent={setHoveredComponent}
            onHypothesisCreated={setHypId}
            importedData={importedCPVData}
          />
          <HypothesisTestPanel 
            position="bottom-center"
            isOpen={showHypothesisTestPanel} 
            onClose={() => handleTestPanelOpen(false)}
            hypothesis={hypothesis}
            device={device}
            bpId={bpId || ''}
            onSimulationHover={handleSimulationHover}
          />
        </Flow>
      </div>
    </>
  );
}

export default App;
