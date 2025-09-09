import { Position, Handle } from "@xyflow/react";
import { useState } from "react";
import { Plus } from "react-feather";

export type CustomNodeData = {
  label: string;
  numberOfAnnotations: number;
  onAnnotationClick: (nodeId: string) => void;
  isAnnotationOpen?: boolean;
};

type CustomNodeProps = {
  id: string;
  data: CustomNodeData;
};

// Custom node component with annotation button
export const CustomNode = ({ id, data }: CustomNodeProps) => {
    const [hover, setHover] = useState(false);
    
    const hasAnnotations = data.numberOfAnnotations > 0;
    const isAnnotationOpen = data.isAnnotationOpen || false;
    
    return (
      <div onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}>
        {/* Add proper handles for the node connections */}
        <Handle type="target" position={Position.Top} />
        <Handle type="source" position={Position.Bottom} />
        
        {data.label}
        
        {/* Annotation button - shown always if has annotations, or on hover/open if empty */}
        <div 
          className={`annotation-button absolute -top-2 -right-2 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold transition-all duration-200 cursor-pointer z-10
            ${hasAnnotations 
              ? 'bg-indigo-600 text-white shadow-md'
              : (hover || isAnnotationOpen)
                ? 'bg-gray-200 text-gray-600 dark:bg-gray-700 dark:text-gray-300 opacity-100 scale-100'
                : 'opacity-0 scale-75'
            }`}
          onClick={(e) => {
            // Prevent clicking the node when clicking the annotation button
            e.stopPropagation();
            data.onAnnotationClick(id);
          }}
        >
          {hasAnnotations 
            ? data.numberOfAnnotations 
            : <Plus size={14} className="stroke-2" />
          }
        </div>
      </div>
    );
};
