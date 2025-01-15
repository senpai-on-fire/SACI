import { useEffect, useState } from 'react';
import { ReactFlow } from '@xyflow/react';
import { useSWR } from 'swr';
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

const fetcher = (...args) => fetch(...args).then(res => res.json());

function Hypothesis({hypothesis}) {
  return (
    <> </>
  );
}

function Flow({device}) {
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
      <ReactFlow nodes={state.nodes} edges={state.edges}>
      </ReactFlow>
    );
  }
}

function DeviceSelector({selected, onSelection}: {selected: number, onSelection: (idx: number) => void}) {
  // TODO: do a request here? or should that be bubbled up higher?
  const options = DEVICES.map((d, i) => <option key={i} value={`${i}`}>{d.name}</option>);
  return (
    <label>
      Device under examination:
      <select value={`${selected}`} onChange={e => onSelection(parseInt(e.target.value))}>
        {options}
      </select>
    </label>
  );
}

function App() {
  const [deviceIdx, setDeviceIdx] = useState(0);

  return (
    <>
      <h1>SACI</h1>
      <DeviceSelector selected={deviceIdx} onSelection={setDeviceIdx} />
      <div style={{ width: '800px', height: '400px'}}>
        <Flow device={DEVICES[deviceIdx]} />
      </div>
    </>
  );
}

export default App;
