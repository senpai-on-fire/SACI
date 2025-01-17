import { useEffect, useState } from 'react';
import { ReactFlow, Background, Controls, Panel } from '@xyflow/react';
import useSWR from 'swr';
import ELK from 'elkjs/lib/elk-api';
 
import './App.css';
import '@xyflow/react/dist/style.css';

const elk = new ELK({
  workerFactory: () =>
    new Worker(new URL('elkjs/lib/elk-worker.min.js', import.meta.url)),
});

const ROVER1 = {
  name: "Rover",
  components: {
    'wifi': {
      'parameters': {
      },
    },
    'serial': {
      'parameters': {
        'baud rate': 115200
      },
    },
    'webserver': {},
    'gps': {},
    'compass': {},
    'uno_r4': {},
    'esc': {},
    'motor': {},
    'steering': {},
    'uno_r3': {},
  },
  connections: [
    ['wifi', 'webserver'],
    ['webserver', 'uno_r4'],
    ['gps', 'uno_r4'],
    ['compass', 'uno_r4'],
    ['serial', 'uno_r4'],
    ['uno_r4', 'uno_r3'],
    ['uno_r3', 'esc'],    
    ['uno_r3', 'steering'],
    ['esc', 'motor'],
  ],
};
const ROVER2 = {
  name: "Rover 2",
  components: {
    'wifi': {
      'parameters': {
      },
    },
    'serial': {
      'parameters': {
      },
    },
    'webserver': {},
    'gps': {},
    'magnetometer': {},
    'uno_r4': {},
    'esc': {},
    'motor': {},
    'steering': {},
    'uno_r3': {},
  },
  connections: [
    ['wifi', 'webserver'],
    ['webserver', 'uno_r4'],
    ['gps', 'uno_r4'],
    ['magnetometer', 'uno_r4'],
    ['serial', 'uno_r4'],
    ['uno_r4', 'uno_r3'],
    ['uno_r3', 'esc'],    
    ['uno_r3', 'steering'],
    ['esc', 'motor'],
  ],
};
const DEVICES = [ROVER1, ROVER2];

const fetcher = async (...args) => {
  const res = await fetch(...args);

  if (res.ok) {
    return await res.json();
  } else {
    const error = new Error('error while fetching');
    error.info = await res.json();
    error.status = res.status;
    throw error;
  }
};

function Hypothesis({hypothesis}) {
  return (
    <> </>
  );
}

function Flow({device, onComponentClick, children}) {
  type GraphLayoutState =
    {state: "laying"} |
    {state: "laid", nodes: any, edges: any} |
    {state: "error"};
  const [state, setState] = useState<GraphLayoutState>({state: "laying"});

  useEffect(() => {
    const elkGraph = {
      id: "root",
      layoutOptions: {
        'elk.algorithm': 'layered',
        'elk.direction': 'DOWN',
        'elk.spacing.nodeNode': 200,
        'elk.spacing.edgeNode': 200,
        'elk.layered.spacing.nodeNodeBetweenLayers': 75
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
           nodes: layout.children.map(n => ({
             id: n.id,
             data: {label: n.id},
             position: {
               x: n.x,
               y: n.y
             },
             ...device.components[n.id]
           })),
           edges: layout.edges.map(e => ({
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

  if (state.state === "laying") {
    return <p>laying out the graph...</p>;
  } else if (state.state == "error") {
    return <p>error laying it out??</p>;
  } else {
    return (
      <ReactFlow
        onNodeClick={(_e, n) => onComponentClick(n.id)}
        colorMode="system"
        nodes={state.nodes}
        edges={state.edges}
      >
        <Background />
        <Controls />
        {children}
      </ReactFlow>
    );
  }
}

function DeviceSelector({selected, onSelection}: {selected: number, onSelection: (idx: number) => void}) {
  // TODO: do a request here? or should that be bubbled up higher?
  const options = DEVICES.map((d, i) => <option key={i} value={`${i}`}>{d.name}</option>);
  return (
    <div>
      <label>
        Device:&nbsp;
        <select value={`${selected}`} onChange={e => onSelection(parseInt(e.target.value))}>
          {options}
        </select>
      </label>
    </div>
  );
}

function Component({component}) {
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

function CPV({name}) {
  const { data, error, isLoading } = useSWR(`/api/cpv_info?name=${name}`, fetcher);
  console.log(error);

  if (error) {
    return <div>Error loading CPV {name}</div>;
  } else if (isLoading) {
    return <div>Loading CPV {name}</div>;
  } else {
    return (
      <div>
        {data.name} has entry {data.entry_component} and exit {data.exit_component}
      </div>
    );
  }
}

function App() {
  const [deviceIdx, setDeviceIdx] = useState(0);
  const device = DEVICES[deviceIdx];

  type PanelState =
    {state: "cpv", id: string} |
    {state: "component", id: string};
  const [panel, setPanel] = useState<PanelState>({state: "cpv", id: "MavlinkCPV"});

  let panelInnerComp;
  if (panel.state === "cpv") {
    panelInnerComp = <CPV name={panel.id} />;
  } else if (panel.state === "component") {
    panelInnerComp = <Component component={{name: panel.id, ...device.components[panel.id]}} />;
  }
  const panelComponent = (
    <Panel className="bg-white dark:bg-neutral-900 p-4" position="bottom-center">
      {panelInnerComp}
    </Panel>
  );

  return (
    <>
      <div style={{ width: '100vw', height: '100vh'}}>
        <Flow device={device} onComponentClick={id => setPanel({state: "component", id})}>
          <div className="m-8">
            <h1 className="font-bold">SACI</h1>
            <DeviceSelector selected={deviceIdx} onSelection={setDeviceIdx} />
          </div>
          {panelComponent}
        </Flow>
      </div>
    </>
  );
}

export default App;
