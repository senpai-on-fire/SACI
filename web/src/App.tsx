import { useEffect, useState } from 'react';
import reactLogo from './assets/react.svg';
import viteLogo from '/vite.svg';
import { ReactFlow } from '@xyflow/react';
import { useSWR } from 'swr';
import ELK from 'elkjs/lib/elk-api';
 
import './App.css';
import '@xyflow/react/dist/style.css';

const elk = new ELK({
  workerFactory: () =>
    new Worker(new URL('elkjs/lib/elk-worker.min.js', import.meta.url)),
});

const initialNodes = {
  '1': { data: { label: '1' } },
  '2': { data: { label: '2' } }
};
const initialEdges = {
  'e1-2': { source: '1', target: '2' }
};

const fetcher = (...args) => fetch(...args).then(res => res.json());

function Flow({graph}) {
  type GraphLayoutState =
    {state: "laying"} |
    {state: "laid", nodes: any, edges: any} |
    {state: "error"};
  const [state, setState] = useState<GraphLayoutState>({state: "laying"});
  console.log(graph);

  useEffect(() => {
    const elkGraph = {
      id: "root",
      layoutOptions: {
        'elk.algorithm': 'layered',
        'elk.direction': 'DOWN',
        'elk.spacing.nodeNode': 200,
        'elk.spacing.edgeNode': 200,
        'elk.layered.spacing.nodeNodeBetweenLayers': 200
      },
      children: Object.keys(graph.nodes).map(id => ({
        id
      })),
      edges: Object.entries(graph.edges).map(([id, e]) => ({
        id,
        sources: [e.source],
        targets: [e.target]
      }))
    };
    elk.layout(elkGraph)
       .then(layout => {
         setState({
           state: "laid",
           nodes: layout.children.map(n => ({
             id: n.id,
             position: {
               x: n.x,
               y: n.y
             },
             ...graph.nodes[n.id]
           })),
           edges: layout.edges.map(e => ({
             id: e.id,
             source: e.sources[0],
             target: e.targets[0],
             ...graph.edges[e.id]
           }))
         });
       })
      .catch(e => {
        console.log(e);
        setState({state: "error"});
      });
  }, [graph]);

  if (state.state === "laying") {
    return <p>laying out the graph...</p>;
  } else if (state.state == "error") {
    return <p>error laying it out??</p>;
  } else {
    return <ReactFlow nodes={state.nodes} edges={state.edges} />;
  }
}

function App() {
  const [count, setCount] = useState(0);

  return (
    <>
      <div>
        <a href="https://vite.dev" target="_blank">
          <img src={viteLogo} className="logo" alt="Vite logo" />
        </a>
        <a href="https://react.dev" target="_blank">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </div>
      <h1>Vite + React</h1>
      <div className="card">
        <button onClick={() => setCount((count) => count + 1)}>
          count is now {count}
        </button>
        <p>
          Edit <code>src/App.tsx</code> and save to test HMR
        </p>
      </div>
      <p className="read-the-docs">
        Click on the Vite and React logos to learn more
      </p>
      <div style={{ width: '600px', height: '400px'}}>
        <Flow graph={{nodes: initialNodes, edges: initialEdges}} />
      </div>
    </>
  );
}

export default App;
