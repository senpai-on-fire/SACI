import { ReactNode, useEffect, useState } from 'react';
import { ReactFlow, Background, Panel, PanelPosition } from '@xyflow/react';
import useSWR from 'swr';
import ELK from 'elkjs/lib/elk-api';
import { VncScreen } from 'react-vnc';
import { Maximize2, Minimize2 } from 'react-feather';
 
import './App.css';
import '@xyflow/react/dist/style.css';

const elk = new ELK({
  workerFactory: () =>
    new Worker(new URL('elkjs/lib/elk-worker.min.js', import.meta.url)),
});

type Component = {
  name: string,
  parameters?: {[name: string]: string | number | boolean | null},
};

type Device = {
  name: string,
  components: {[name: string]: Component},
  connections: [from: string, to: string][],
};

class FetchError extends Error {
  info: unknown;
  status?: number;
}

const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
  const res = await fetch(input, init);

  if (res.ok) {
    return await res.json();
  } else {
    const error = new FetchError('error while fetching');
    error.info = await res.json();
    error.status = res.status;
    throw error;
  }
};

/*
function Hypothesis({hypothesis}) {
  return (
    <> </>
  );
}
 */

type ActiveCPV = {
  deviceName: string;
  index: number;
  path: string[];
} | undefined;

type HighlightProps = {
  entry?: string | null,
  exit?: string | null,
  involved?: string[] | null,
  activePath?: string[],
};

type FlowProps = {
  device?: Device,
  onComponentClick?: (componentName: string) => void,
  onPaneClick?: () => void,
  children: ReactNode,
  highlights?: HighlightProps,
};
function Flow({device, onComponentClick, onPaneClick, children, highlights}: FlowProps) {
  type GraphLayoutState =
    {state: "laying"} |
    {state: "laid", compLayout: {[compId: string]: {x: number, y: number}}, forDevice: Device} |
    {state: "error"} |
    {state: "nodevice"};
  const [state, setState] = useState<GraphLayoutState>({state: "laying"});

  useEffect(() => {
    if (!device) {
      setState({state: "nodevice"});
      return;
    }
    setState({state: "laying"});
    const elkGraph = {
      id: "root",
      layoutOptions: {
        'elk.algorithm': 'layered',
        'elk.direction': 'DOWN',
        'elk.spacing.nodeNode': '200',
        'elk.spacing.edgeNode': '200',
        'elk.layered.spacing.nodeNodeBetweenLayers': '75',
      },
      children: Object.keys(device.components).map(id => ({
        id
      })),
      edges: device.connections.map(([source, target]) => ({
        id: `${source}-${target}`,
        sources: [source],
        targets: [target]
      }))
    };
    elk.layout(elkGraph)
       .then(layout => {
         const compLayout: {[compId: string]: {x: number, y: number}} = {};
         for (const node of layout.children ?? []) {
           compLayout[node.id] = {x: node.x ?? 0, y: node.y ?? 0};
         }
         setState({
           state: "laid",
           forDevice: device,
           compLayout,
         });
       })
      .catch(e => {
        console.log(e);
        setState({state: "error"});
      });
  }, [device]);

  let statusPanel, nodes, edges: {id: string, source: string, target: string, animated?: boolean, style?: React.CSSProperties}[];
  if (state.state === "laying") {
    statusPanel = <Panel position="bottom-right">laying out the graph...</Panel>;
    nodes = edges = [];
  } else if (state.state === "error") {
    statusPanel = <Panel position="bottom-right">error laying it out??</Panel>;
    nodes = edges = [];
  } else if (state.state === "nodevice") {
    statusPanel = <Panel position="bottom-right">waiting for device...</Panel>;
    nodes = edges = [];
  } else if (device && Object.is(device, state.forDevice)) {
    statusPanel = <> </>;
    nodes = Object.entries(device.components).map(([compId, comp]) => {
      let className = '';
      if (compId === highlights?.entry) {
        className = "!border-green-500";
      } else if (compId === highlights?.exit) {
        className = "!border-red-500";
      } else if (highlights?.involved?.includes(compId)) {
        className = "!border-yellow-500";
      } else if (highlights?.activePath?.includes(compId)) {
        className = "!border-indigo-500 !border-2 !shadow-lg !shadow-indigo-200 dark:!shadow-indigo-900";
      }
      
      const position = state.compLayout[compId];
      return {
        id: compId,
        data: {label: comp.name},
        position,
        className,
      };
    });

    edges = [];
    for (const [from, to] of device.connections) {
      const isAnimated = highlights?.activePath && 
                        highlights.activePath.length > 1 && 
                        highlights.activePath.indexOf(from) !== -1 && 
                        highlights.activePath.indexOf(to) === highlights.activePath.indexOf(from) + 1;
                        
      edges.push({
        id: `${from}-${to}`,
        source: from,
        target: to,
        animated: isAnimated,
        style: isAnimated ? { stroke: '#6366f1', strokeWidth: 2 } : undefined,
      });
    }
  } else {
    statusPanel = <> </>;
    // wait for the nodevice state to take hold...
    nodes = edges = [];
  }

  return (
    <ReactFlow
      onNodeClick={(_e, n) => onComponentClick ? onComponentClick(n.id) : undefined}
      onPaneClick={onPaneClick}
      colorMode="system"
      nodes={nodes}
      edges={edges}
    >
      <Background />
      {children}
      {statusPanel}
    </ReactFlow>
  );
}

type BlueprintID = string;
type DeviceSelectorProps = {
  devices?: {[bpId: string]: Device}, /// should be null/undefined when devices are still loading
  selected?: string | null,
  onSelection: (bpId: string) => void,
};
function DeviceSelector({devices, selected, onSelection}: DeviceSelectorProps) {
  // TODO: do a request here? or should that be bubbled up higher?
  const options = devices ?
    Object.entries(devices).map(([bpId, d]) => <option key={bpId} value={bpId}>{d.name}</option>) :
    [<option key={null} value="0">loading...</option>];
  return (
    <div>
      <label>
        Device:&nbsp;
          <select
            value={`${devices ? selected : 0}`}
            onChange={e => onSelection(e.target.value)}
            disabled={!devices} >
          {options}
        </select>
      </label>
    </div>
  );
}

type HypothesisId = string;
type Hypothesis = {
  name: string,
  entry_component?: string | null,
  exit_component?: string | null,
};
type HypothesisSelectorProps = {
  hypotheses?: {[hypId: HypothesisId]: Hypothesis} | null,
  selected: string | null,
  onSelection: (hypId: HypothesisId) => void,
};
function HypothesisSelector({hypotheses, selected, onSelection}: HypothesisSelectorProps) {
  // TODO: this JSON.stringify for the value seems like a hack. Is there a better way of storing
  // non-string values for the value? Or a way to access the key?
  const options = hypotheses ?
    [<option key={null} value="null">none</option>].concat(
      Object.entries(hypotheses).map(([hypId, d]) =>
        <option key={hypId} value={JSON.stringify(hypId)}>{d.name}</option>
      )
    ) :
    [<option key={null} value="null">loading...</option>];
  return (
    <div>
      <label>
        Hypothesis:&nbsp;
          <select
            value={`${hypotheses ? JSON.stringify(selected) : null}`}
            onChange={e => onSelection(JSON.parse(e.target.value))}
            disabled={!hypotheses} >
          {options}
        </select>
      </label>
    </div>
  );
}

/*
function CPV({name}: {name: string}) {
  const { data, error, isLoading } = useSWR(`/api/cpv_info?name=${name}`, fetcher);

  if (error) {
    return <div>Error loading CPV {name}: {error}</div>;
  } else if (isLoading) {
    return <div>Loading CPV {name}...</div>;
  } else {
    return (
      <div>
        {data.name} has entry {data.entry_component} and exit {data.exit_component}
      </div>
    );
  }
}
 */

type AnalysisInfo = {
  name: string,
  components_included: string[],
};
type AnalysisLauncherProps = {
  bpId: BlueprintID,
  analysisId: string,
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
  bpId: string,
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
        <h3 className="text-2xl font-bold">Analyses</h3>
        <ul>
          {analyses}
        </ul>
      </div>
    );
  }
}

type ComponentPanelProps = {
  componentId: string,
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
        analysisFilter={info => info.components_included.includes(componentId) &&
                                (!analysisFilter || analysisFilter(info))}
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
    <div className="flex-none text-xl"><button onClick={onClose}>✕</button> {name}</div>
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
    {hypothesis.entry_component ?
      <div>Entry: {device.components[hypothesis.entry_component].name}</div> :
      <> </>}
    {hypothesis.exit_component ?
      <div>Exit: {device.components[hypothesis.exit_component].name}</div> :
      <> </>}
    <Analyses bpId={bpId} {...analysesProps} />
  </>;
}

type CPVResult = {
  cpv: {name: string},
  path: {path: string[]},
};

function renderCPVs(
  device: Device, 
  cpvs: CPVResult[], 
  activeCPV: ActiveCPV, 
  onCPVClick: (cpv: ActiveCPV) => void
) {
  const cpvItems = cpvs.map(({cpv: {name}, path: {path}}, i) => {
    const isActive = activeCPV && 
                     activeCPV.deviceName === device.name && 
                     activeCPV.index === i;
    
    return (
      <li 
        key={i} 
        className={`cursor-pointer hover:text-indigo-600 transition-colors p-2 rounded ${isActive ? 'bg-indigo-50 dark:bg-indigo-900/30' : ''}`}
        onClick={() => {
          if (isActive) {
            onCPVClick(undefined);
          } else {
            onCPVClick({
              deviceName: device.name,
              index: i,
              path: path
            });
          }
        }}
      >
        <div className="font-medium">{name}</div>
        {isActive && (
          <div className="ml-4 text-sm text-gray-600 dark:text-gray-400 mt-1">
            {path.map(compId => device.components[compId].name).join(" -> ")}
          </div>
        )}
      </li>
    );
  });
  return <ul className="space-y-2">{cpvItems}</ul>;
}

function CPVsPanel({
  bpId, 
  device, 
  position, 
  activeCPV, 
  onActiveCPVChange
}: {
  bpId: string | null, 
  device: Device | null, 
  position?: PanelPosition,
  activeCPV: ActiveCPV,
  onActiveCPVChange: (cpv: ActiveCPV) => void
}) {
  // Define hook at the top level, even if we might not use the data
  const { data, error, isLoading } = useSWR(
    bpId !== null ? `/api/blueprints/${bpId}/cpvs` : null, 
    fetcher
  );

  if (bpId === null || device === null) {
    return <> </>;
  }

  let panelInner;
  if (error) {
    panelInner = <div>Error loading CPVs: {error}</div>;
  } else if (isLoading) {
    panelInner = <div>Loading applicable CPVs...</div>;
  } else if (data) {
    panelInner = renderCPVs(device, data as CPVResult[], activeCPV, onActiveCPVChange);
  } else {
    panelInner = <div>No data available</div>;
  }

  return (
    <Panel 
      className="bg-white dark:bg-neutral-900 border-2 border-indigo-600 rounded max-w-md" 
      position={position}
    >
      <div className="flex flex-col max-h-[90vh] overflow-auto">
        <h3 className="text-2xl font-bold sticky top-0 bg-white dark:bg-neutral-900 p-4 z-10">CPVs</h3>
        <div className="p-4 pt-0">
          {panelInner}
        </div>
      </div>
    </Panel>
  );
}

function App() {
  const { data: devices } = useSWR("/api/blueprints", fetcher);

  const [bpId, setBpId] = useState<string | null>(null);
  // TODO: is there a less janky way to have this "default"?
  useEffect(() => {
    const bpIds = devices ? Object.keys(devices) : [];
    if (!bpId && bpIds.length > 0) {
      setBpId(bpIds[0]);
    }
  }, [devices, bpId]);
  const device = devices && bpId ? devices[bpId] : null;

  const [hypId, setHypId] = useState<HypothesisId | null>(null);
  const hypothesis = device && hypId ? device.hypotheses[hypId] : null;

  const [hoveringAnalysis, setHoveringAnalysis] = useState<AnalysisInfo | null>(null);

  const [selectedComponent, setSelectedComponent] = useState<string | null>(null);

  type RunningAnalysis = {name: string, app: number};
  const [showingAnalysis, setShowingAnalysis] = useState<RunningAnalysis | null>(null);
  const analysisPanel = showingAnalysis ?
    <AnalysisPanel name={showingAnalysis.name} app={showingAnalysis.app} onClose={() => setShowingAnalysis(null)} /> :
    <> </>;

  // Add panel minimization state
  const [panelMinimized, setPanelMinimized] = useState(true);

  // Add activeCPV state
  const [activeCPV, setActiveCPV] = useState<ActiveCPV>(undefined);

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
  
  // Modified panel with minimization controls
  const panel = panelInner ? (
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
  );

  const cpvsPanel = <CPVsPanel 
    bpId={bpId} 
    device={device} 
    position="top-right" 
    activeCPV={activeCPV}
    onActiveCPVChange={setActiveCPV}
  />;

  const highlights = {
    entry: hypothesis?.entry_component,
    exit: hypothesis?.exit_component,
    involved: hoveringAnalysis?.components_included,
    activePath: activeCPV?.path,
  };

  return (
    <>
      <div style={{ width: '100vw', height: '100vh'}}>
        <Flow
          device={device}
          highlights={highlights}
          onComponentClick={setSelectedComponent}
          onPaneClick={() => setSelectedComponent(null)} >
          <Panel className="p-4" position="top-left">
            <h1 className="font-bold">SACI</h1>
            <DeviceSelector devices={devices} selected={bpId} onSelection={setBpId} />
            <HypothesisSelector hypotheses={device?.hypotheses} selected={hypId} onSelection={setHypId} />
          </Panel>
          {panel}
          {analysisPanel}
          {cpvsPanel}
        </Flow>
      </div>
    </>
  );
}

export default App;
