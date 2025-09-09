import { ReactNode, useCallback, useEffect, useState } from 'react';
import { ReactFlow, Background, Panel, Node, Edge } from '@xyflow/react';
import ELK from 'elkjs/lib/elk-api';
import { CustomNode } from './CustomNode';
import { AnnotationNode, AnnotationNodeData } from './AnnotationNode';
import { BlueprintId, ComponentId, Device } from '../types';
import { groupAnnotationsByComponentId } from '../utils/helpers';

// Create a new ELK instance for layout
const elk = new ELK({
  workerFactory: () =>
    new Worker(new URL('elkjs/lib/elk-worker.min.js', import.meta.url)),
});

// Create node types for ReactFlow
const nodeTypes = {
  custom: CustomNode,
  annotation: AnnotationNode
};

// Type definitions for Flow component
type HighlightProps = {
  entry?: string | null,
  exit?: string | null,
  involved?: string[] | null,
  activePath?: string[],
  hoveredComponent?: ComponentId | null, // Component ID that's being hovered in another UI component
  hypothesisPath?: string[] | null,
};

type FlowProps = {
  bpId: BlueprintId | null,
  device?: Device,
  onComponentClick?: (componentId: ComponentId) => void,
  onPaneClick?: () => void,
  children: ReactNode,
  highlights?: HighlightProps,
};

// Flow component
export function Flow({bpId, device, onComponentClick, onPaneClick, children, highlights}: FlowProps) {
  // bpId is kept for future reference but not currently used
  
  type GraphLayoutState =
    {state: "laying"} |
    {state: "laid", compLayout: {[compId: string]: {x: number, y: number}}, forDevice: Device} |
    {state: "error"} |
    {state: "nodevice"};
  const [state, setState] = useState<GraphLayoutState>({state: "laying"});
  
  // State to track the active annotation node
  const [activeAnnotationNode, setActiveAnnotationNode] = useState<string | null>(null);
  
  // Handler for annotation button clicks
  const handleAnnotationClick = useCallback((nodeId: string) => {
    setActiveAnnotationNode(current => current === nodeId ? null : nodeId);
  }, []);
  
  // Handler for closing annotation nodes
  const handleCloseAnnotation = useCallback(() => {
    setActiveAnnotationNode(null);
  }, []);

  useEffect(() => {
    if (!device) {
      setState({state: "nodevice"});
      return;
    }
    
    // Reset annotation state when device changes
    setActiveAnnotationNode(null);
    
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

  let statusPanel;
  let nodes: Node[] = [];
  let edges: Edge[] = [];
  
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
    
    const groupedAnnotations = groupAnnotationsByComponentId(device.annotations);

    // Filter highlights to only include components that exist in the current device
    const safeHighlights = {
      ...highlights,
      involved: highlights?.involved?.filter(compId => device.components[compId]) || null,
      activePath: highlights?.activePath?.filter(compId => device.components[compId]) || null,
      hypothesisPath: highlights?.hypothesisPath?.filter(compId => device.components[compId]) || null,
      hoveredComponent: highlights?.hoveredComponent && device.components[highlights.hoveredComponent] ? highlights.hoveredComponent : null,
    };

    // Create the regular nodes
    nodes = Object.entries(device.components).map(([compId, comp]) => {
      let className = 'react-flow__node-default ';
      if (compId === highlights?.hoveredComponent) {
        className += "!border-purple-500 !border-2 !shadow-lg !shadow-purple-200 dark:!shadow-purple-900";
      } else if (highlights?.involved?.includes(compId)) {
        className += "!border-yellow-500 !border-2 !shadow-lg !shadow-yellow-200 dark:!shadow-yellow-900";
      } else if (highlights?.activePath?.includes(compId)) {
        className += "!border-indigo-500 !border-2 !shadow-lg !shadow-indigo-200 dark:!shadow-indigo-900";
      } else if (highlights?.hypothesisPath?.includes(compId)) {
        className += "!border-indigo-500 !border-2 !shadow-lg !shadow-indigo-200 dark:!shadow-indigo-900";
      }
      className = className.trim();
      
      const position = state.compLayout[compId];
      
      return {
        id: compId,
        data: { 
          label: comp.name,
          numberOfAnnotations: Object.keys(groupedAnnotations[compId] ?? {}).length ?? 0,
          onAnnotationClick: handleAnnotationClick,
          isAnnotationOpen: compId === activeAnnotationNode,
        },
        position,
        className,
        type: 'custom', // Use our custom node
      };
    });
    
    // Add annotation node if active and component exists in current device
    const compId = activeAnnotationNode;
    if (compId && device.components[compId]) {
      const sourceNode = nodes.find(node => node.id === compId);
      if (sourceNode) {
        const annotationNodeId = `annotation-${compId}`;
        // Position to the right of the source node
        const position = {
          x: sourceNode.position.x + 170,
          y: sourceNode.position.y - 30
        };
        
        // Group annotations by attack_surface for this specific node
        const groupedAnnotations = groupAnnotationsByComponentId(device.annotations);
        
        // Add the annotation node
        nodes.push({
          id: annotationNodeId,
          type: 'annotation',
          data: {
            annotations: groupedAnnotations[compId],
            onClose: handleCloseAnnotation,
            onAnnotationClick: handleAnnotationClick,
            onAddAnnotation: (effect: string, attackModel: string) => {
              console.log('Added annotation:', {
                bpId,
                attackSurface: compId,
                effect,
                attackModel
              });
              // We now handle this in the AnnotationNode component
            },
            bpId,
            compId
          } as AnnotationNodeData,
          position,
          className: 'annotation-node'
        });
        
        // Create edges for device connections only (no annotation edges)
        edges = device.connections.map(([from, to]) => {
          const isAnimated = Boolean(
            (safeHighlights?.activePath && 
            safeHighlights.activePath.length > 1 && 
            safeHighlights.activePath.indexOf(from) !== -1 && 
            safeHighlights.activePath.indexOf(to) === safeHighlights.activePath.indexOf(from) + 1) ||
            (safeHighlights?.hypothesisPath &&
            safeHighlights.hypothesisPath.length > 1 &&
            safeHighlights.hypothesisPath.indexOf(from) !== -1 &&
            safeHighlights.hypothesisPath.indexOf(to) === safeHighlights.hypothesisPath.indexOf(from) + 1)
          );
                          
          return {
            id: `${from}-${to}`,
            source: from,
            target: to,
            animated: isAnimated,
            style: isAnimated ? { stroke: '#6366f1', strokeWidth: 2 } : undefined,
          };
        });
      } else {
        edges = device.connections.map(([from, to]) => {
          const isAnimated = Boolean(
            (safeHighlights?.activePath && 
            safeHighlights.activePath.length > 1 && 
            safeHighlights.activePath.indexOf(from) !== -1 && 
            safeHighlights.activePath.indexOf(to) === safeHighlights.activePath.indexOf(from) + 1) ||
            (safeHighlights?.hypothesisPath &&
            safeHighlights.hypothesisPath.length > 1 &&
            safeHighlights.hypothesisPath.indexOf(from) !== -1 &&
            safeHighlights.hypothesisPath.indexOf(to) === safeHighlights.hypothesisPath.indexOf(from) + 1)
          );
                          
          return {
            id: `${from}-${to}`,
            source: from,
            target: to,
            animated: isAnimated,
            style: isAnimated ? { stroke: '#6366f1', strokeWidth: 2 } : undefined,
          };
        });
      }
    } else {
      edges = device.connections.map(([from, to]) => {
        const isAnimated = Boolean(
          (safeHighlights?.activePath && 
          safeHighlights.activePath.length > 1 && 
          safeHighlights.activePath.indexOf(from) !== -1 && 
          safeHighlights.activePath.indexOf(to) === safeHighlights.activePath.indexOf(from) + 1) ||
          (safeHighlights?.hypothesisPath &&
          safeHighlights.hypothesisPath.length > 1 &&
          safeHighlights.hypothesisPath.indexOf(from) !== -1 &&
          safeHighlights.hypothesisPath.indexOf(to) === safeHighlights.hypothesisPath.indexOf(from) + 1)
        );
                        
        return {
          id: `${from}-${to}`,
          source: from,
          target: to,
          animated: isAnimated,
          style: isAnimated ? { stroke: '#6366f1', strokeWidth: 2 } : undefined,
        };
      });
    }
  } else {
    statusPanel = <> </>;
    // wait for the nodevice state to take hold...
    nodes = edges = [];
  }

  return (
    <ReactFlow
      onNodeClick={(_e, n) => {
        if (!n.id.startsWith('annotation-') && onComponentClick) {
          onComponentClick(n.id as ComponentId);
        }
      }}
      onPaneClick={() => {
        setActiveAnnotationNode(null);
        if (onPaneClick) onPaneClick();
      }}
      colorMode="system"
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      defaultViewport={{ x: 20, y: 120, zoom: 1 }}
    >
      <Background />
      {children}
      {statusPanel}
    </ReactFlow>
  );
} 