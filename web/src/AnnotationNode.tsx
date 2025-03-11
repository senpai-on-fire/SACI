import { Annotation } from './CustomNode';
import { useEffect, useState } from 'react';

// Define a separate type for the data
export type AnnotationNodeData = {
  label: string;
  annotations: Annotation[];
  deviceName: string;
  componentName: string;
  onAnnotationClick: (nodeId: string) => void;
  onClose: () => void;
  onAddAnnotation?: (annotation: Annotation) => void;
};

type AnnotationNodeProps = {
  id: string;
  data: AnnotationNodeData;
};

export const AnnotationNode = ({ data }: AnnotationNodeProps) => {
  const [isVisible, setIsVisible] = useState(false);
  const [newAttack, setNewAttack] = useState('');
  const [newEffect, setNewEffect] = useState('');
  const [attackFocused, setAttackFocused] = useState(false);
  const [effectFocused, setEffectFocused] = useState(false);
  
  // Add an entrance animation effect
  useEffect(() => {
    const timer = setTimeout(() => {
      setIsVisible(true);
    }, 50);
    return () => clearTimeout(timer);
  }, []);

  // Handle adding a new annotation
  const handleAddAnnotation = (e: React.FormEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    if (newAttack.trim() && newEffect.trim()) {
      // Create a new annotation object
      const newAnnotation: Annotation = {
        attack: newAttack.trim(),
        effect: newEffect.trim()
      };
      
      // Pass the new annotation to the parent component if handler exists
      if (data.onAddAnnotation) {
        data.onAddAnnotation(newAnnotation);
      } else {
        // Fallback to console logging if no handler
        console.log('New annotation:', newAnnotation);
      }
      
      // Reset input fields
      setNewAttack('');
      setNewEffect('');
    }
  };

  // Handle key press in the effect input field
  const handleEffectKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleAddAnnotation(e);
    }
  };

  return (
    <div 
      className={`rounded-lg overflow-hidden backdrop-blur-sm transition-all duration-300 ease-in-out ${
        isVisible 
          ? 'opacity-100 transform-none' 
          : 'opacity-0 translate-x-4'
      }`}
      style={{
        background: 'var(--annotation-bg, rgba(255, 255, 255, 0.85))',
        boxShadow: 'var(--annotation-shadow, 0 4px 15px rgba(0, 0, 0, 0.1), 0 0 0 1px rgba(0, 0, 0, 0.05))',
        cursor: 'pointer'
      }}
      onClick={() => data.onClose()}
    >
      <style>
        {`
          :root {
            --annotation-bg: rgba(255, 255, 255, 0.85);
            --annotation-shadow: 0 4px 15px rgba(0, 0, 0, 0.1), 0 0 0 1px rgba(0, 0, 0, 0.05);
          }
          
          @media (prefers-color-scheme: dark) {
            :root {
              --annotation-bg: rgba(31, 41, 55, 0.85);
              --annotation-shadow: 0 4px 15px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(0, 0, 0, 0.2);
            }
          }
        `}
      </style>
      <table 
        className="w-full border-collapse" 
        onClick={(e) => e.stopPropagation()}
      >
        <thead>
          <tr className="text-xs font-semibold text-gray-600 dark:text-gray-300 bg-gradient-to-r from-indigo-50 to-transparent dark:from-indigo-900/20 dark:to-transparent">
            <th className="text-center py-2 px-3">Attack</th>
            <th className="text-center py-2 px-3">Effect</th>
          </tr>
        </thead>
        <tbody>
          {data.annotations.map((annotation, index) => (
            <tr key={index} className="hover:bg-indigo-50 dark:hover:bg-indigo-900/20 transition-colors border-t border-gray-200 dark:border-gray-700 group relative">
              <td className="py-1.5 px-3 text-xs dark:text-gray-300">{annotation.attack}</td>
              <td className="py-1.5 px-3 text-xs dark:text-gray-300">{annotation.effect}</td>
              <button
                className="absolute right-1 top-1/2 transform -translate-y-1/2 opacity-0 group-hover:opacity-70 transition-opacity text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 rounded-full p-0.5 hover:bg-gray-100 dark:hover:bg-gray-700 focus:outline-none"
                onClick={(e) => e.stopPropagation()}
                aria-label="Remove annotation"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </tr>
          ))}
          {data.annotations.length === 0 && (
            <tr>
              <td colSpan={2} className="py-3 px-3 text-xs text-center text-gray-500 dark:text-gray-400">No annotations</td>
            </tr>
          )}
          {/* Add a row with input fields */}
          <tr className="border-t border-gray-200 dark:border-gray-700 bg-gradient-to-b from-transparent to-indigo-50/30 dark:to-indigo-900/10">
            <td className="p-1 relative">
              <input
                type="text"
                placeholder="Attack"
                className="w-full text-xs p-1.5 pr-10 rounded border border-gray-200 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-300 dark:placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-indigo-400 dark:focus:ring-indigo-500"
                value={newAttack}
                onChange={(e) => setNewAttack(e.target.value)}
                onClick={(e) => e.stopPropagation()}
                onFocus={() => setAttackFocused(true)}
                onBlur={() => setAttackFocused(false)}
              />
              {attackFocused && (
                <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-300 dark:text-gray-500 pointer-events-none flex items-center opacity-70">
                  <span className="mr-0.5 text-[10px]">tab</span>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M9 18l6-6-6-6"></path>
                  </svg>
                </div>
              )}
            </td>
            <td className="p-1 relative">
              <input
                type="text"
                placeholder="Effect"
                className="w-full text-xs p-1.5 pr-14 rounded border border-gray-200 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-300 dark:placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-indigo-400 dark:focus:ring-indigo-500"
                value={newEffect}
                onChange={(e) => setNewEffect(e.target.value)}
                onClick={(e) => e.stopPropagation()}
                onFocus={() => setEffectFocused(true)}
                onBlur={() => setEffectFocused(false)}
                onKeyDown={handleEffectKeyDown}
              />
              {effectFocused && (
                <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-300 dark:text-gray-500 pointer-events-none flex items-center opacity-70">
                  <span className="mr-0.5 text-[10px]">return</span>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="9 10 4 15 9 20"></polyline>
                    <path d="M20 4v7a4 4 0 0 1-4 4H4"></path>
                  </svg>
                </div>
              )}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}; 