import { ReactNode, useEffect, useState } from 'react';
import { ReactFlow, Background, Controls, Panel } from '@xyflow/react';
import useSWR from 'swr';
import ELK from 'elkjs/lib/elk-api';
 
import './App.css';
import '@xyflow/react/dist/style.css';

const elk = new ELK({
  workerFactory: () =>
    new Worker(new URL('elkjs/lib/elk-worker.min.js', import.meta.url)),
});

type Component = {
  name: string,
  parameters?: {[name: string]: any},
};

type Device = {
  name: string,
  components: {[name: string]: Component},
  connections: [from: string, to: string][],
};

class FetchError extends Error {
  info: any;
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

type FlowProps = {
  device?: Device,
  onComponentClick?: (componentName: string) => void,
  children: ReactNode,
};
function Flow({device, onComponentClick, children}: FlowProps) {
  type GraphLayoutState =
    {state: "laying"} |
    {state: "laid", nodes: any, edges: any} |
    {state: "error"} |
    {state: "nodevice"};
  const [state, setState] = useState<GraphLayoutState>({state: "laying"});

  useEffect(() => {
    if (!device) {
      setState({state: "nodevice"});
      return;
    }
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
         setState({
           state: "laid",
           nodes: (layout.children ?? []).map(n => ({
             id: n.id,
             data: {label: device.components[n.id].name},
             position: {
               x: n.x,
               y: n.y
             },
           })),
           edges: (layout.edges ?? []).map(e => ({
             id: e.id,
             source: e.sources[0],
             target: e.targets[0],
           }))
         });
       })
      .catch(e => {
        console.log(e);
        setState({state: "error"});
      });
  }, [device]);

  let statusPanel, nodes, edges;
  if (state.state === "laying") {
    statusPanel = <Panel position="bottom-right">laying out the graph...</Panel>;
    nodes = edges = [];
  } else if (state.state === "error") {
    statusPanel = <Panel position="bottom-right">error laying it out??</Panel>;
    nodes = edges = [];
  } else if (state.state === "nodevice") {
    statusPanel = <Panel position="bottom-right">waiting for device...</Panel>;
    nodes = edges = [];
  } else {
    statusPanel = <> </>;
    nodes = state.nodes;
    edges = state.edges;
  }

  return (
    <ReactFlow
      onNodeClick={(_e, n) => onComponentClick ? onComponentClick(n.id) : undefined}
      colorMode="system"
      nodes={nodes}
      edges={edges}
    >
      <Background />
      <Controls />
      {children}
      {statusPanel}
    </ReactFlow>
  );
}

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
  entry_component: string,
  exit_component: string,
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

function Component({component}: {component: Component}) {
  const parameters = Object.entries(component.parameters ?? {}).map(([id, val]) =>
    <li key={id}>{id}: {val}</li>
  );
  return (
    <>
      <h2>{component.name}</h2>
      <ul>
        {parameters}
      </ul>
      <button>Start Simulation</button>
    </>
  );
}

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

type AnalysisInfo = {name: string};
type AnalysisLauncherProps = {
  bpId: string,
  analysisId: string,
  analysisInfo: AnalysisInfo,
  onLaunch: (url: string) => void,
};
function AnalysisLauncher({bpId, analysisId, analysisInfo, onLaunch}: AnalysisLauncherProps) {
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
      const url = await resp.json();
      setLaunchStatus("unlaunched");
      onLaunch(url);
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
      disabled={launchStatus !== "unlaunched"} >
      {analysisInfo.name} {icon}
    </button>
  );
}

type AnalysesProps = {
  bpId: string,
  onLaunch: (name: string, url: string) => void,
};
function Analyses({bpId, onLaunch}: AnalysesProps) {
  // TODO: replace deviceIdx with a blueprint ID. for now it doesn't matter anyway
  const { data, error, isLoading } = useSWR(`/api/blueprints/${bpId}/analyses`, fetcher);

  if (error) {
    return <div>Error loading analyses: {error}</div>;
  } else if (isLoading) {
    return <div>Loading analyses...</div>;
  } else {
    const analyses = Object.entries(data).map(([id, analysisInfo]) =>
      <li className="m-1" key={id}>
        <AnalysisLauncher
          bpId="foo"
          analysisId={id}
          analysisInfo={analysisInfo as AnalysisInfo}
          onLaunch={url => onLaunch((analysisInfo as AnalysisInfo).name, url)} />
      </li>
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

type AnalysisPanelProps = {
  name: string,
  url: string,
  onClose: () => void,
};
function AnalysisPanel({name, url, onClose}: AnalysisPanelProps) {
  // TODO: fix this hacky width/height calc somehow?
  return <Panel className="flex flex-col border-2 border-indigo-600 rounded bg-white dark:bg-neutral-900" style={{width: "calc(100vw - 30px)", height: "calc(100vh - 30px)"}} position="top-left">
    <div className="flex-none text-xl"><button onClick={onClose}>✕</button> {name}</div>
    <iframe className="flex-1" src={url}  />
  </Panel>;
}

type HypothesisPanelProps = {
  device: Device,
  hypothesis: Hypothesis,
};
function HypothesisPanel({device, hypothesis}: HypothesisPanelProps) {
  return <Panel className="bg-white dark:bg-neutral-900 p-4 border-2 border-indigo-600 rounded" position="bottom-right">
    <h3 className="text-2xl font-bold">Hypothesis: {hypothesis.name}</h3>
    <div>Entry: {device.components[hypothesis.entry_component].name}</div>
    <div>Exit: {device.components[hypothesis.exit_component].name}</div>
  </Panel>;
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
  }, [devices]);
  const device = devices && bpId ? devices[bpId] : null;

  const [hypId, setHypId] = useState<HypothesisId | null>(null);
  const hypothesis = device && hypId ? device.hypotheses[hypId] : null;

  type RunningAnalysis = {name: string, url: string};
  const [showingAnalysis, setShowingAnalysis] = useState<RunningAnalysis | null>(null);
  const analysisPanel = showingAnalysis ?
    <AnalysisPanel name={showingAnalysis.name} url={showingAnalysis.url} onClose={() => setShowingAnalysis(null)} /> :
    <> </>;
  const hypothesisPanel = device && hypothesis ?
    <HypothesisPanel device={device} hypothesis={hypothesis} /> :
    <> </>;

  return (
    <>
      <div style={{ width: '100vw', height: '100vh'}}>
        <Flow device={device}>
          <Panel className="p-4" position="top-left">
            <h1 className="font-bold">SACI</h1>
            <DeviceSelector devices={devices} selected={bpId} onSelection={setBpId} />
            <HypothesisSelector hypotheses={device?.hypotheses} selected={hypId} onSelection={setHypId} />
          </Panel>
          {bpId ?
            <Panel className="bg-white dark:bg-neutral-900 p-4 border-2 border-indigo-600 rounded" position="top-right">
              <Analyses bpId={bpId} onLaunch={(name, url) => setShowingAnalysis({name, url})} />
            </Panel> : <> </>}
          {analysisPanel}
          {hypothesisPanel}
        </Flow>
      </div>
    </>
  );
}

export default App;
