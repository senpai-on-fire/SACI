import { useState } from 'react';
import { mutate } from 'swr';
import { postData } from '../utils/api';
import { BlueprintId, ComponentId } from '../types';

type AnnotationNodeProps = {
  id: string;
  data: AnnotationNodeData;
};

export type AnnotationNodeData = {
  annotations: Annotations;
  onClose: () => void;
  onAnnotationClick: (nodeId: string) => void;
  onAddAnnotation: (effect: string, attackModel: string) => void;
  bpId: BlueprintId;
  compId: ComponentId; // The component that this annotation is for (attack_surface)
};

export type Annotations = {
  [annotationId: string]: {
    effect: string;
    attack_model: string;
  }
};

export const AnnotationNode = ({ data }: AnnotationNodeProps) => {
  const [newEffect, setNewEffect] = useState('');
  const [newAttack, setNewAttack] = useState('');
  const [attackFocused, setAttackFocused] = useState(false);
  const [effectFocused, setEffectFocused] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  
  // Handle adding a new annotation
  const handleAddAnnotation = async (e: React.FormEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    if (newEffect.trim() && newAttack.trim()) {
      setIsSubmitting(true);
      
      try {
        // Call the API to create a new annotation using postData utility
        await postData(`/api/blueprints/${data.bpId}/annotation`, {
          attack_surface: data.compId,
          effect: newEffect.trim(),
          attack_model: newAttack.trim()
        });

        // Call the onAddAnnotation prop function
        data.onAddAnnotation(newEffect.trim(), newAttack.trim());
        
        // Mutate SWR cache to refresh blueprints data
        await mutate('/api/blueprints');
        
        // Reset input fields
        setNewEffect('');
        setNewAttack('');
      } catch (error) {
        console.error('Error creating annotation:', error);
        alert('Failed to create annotation: ' + (error instanceof Error ? error.message : 'Unknown error'));
      } finally {
        setIsSubmitting(false);
      }
    }
  };

  // Handle key press in the attack model input field
  const handleEffectKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isSubmitting) {
      handleAddAnnotation(e);
    }
  };

  return (
    <div 
      className="rounded-lg overflow-hidden backdrop-blur-sm opacity-100"
      style={{
        background: 'var(--annotation-bg, rgba(255, 255, 255, 0.85))',
        boxShadow: 'var(--annotation-shadow, 0 4px 15px rgba(0, 0, 0, 0.1), 0 0 0 1px rgba(0, 0, 0, 0.05))',
        cursor: 'pointer'
      }}
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
      
      <table className="w-full border-collapse">
        <thead>
          <tr className="text-xs font-semibold text-gray-600 dark:text-gray-300 bg-gradient-to-r from-indigo-50 to-transparent dark:from-indigo-900/20 dark:to-transparent">
            <th className="text-center py-2 px-3 w-1/2">Attack</th>
            <th colSpan={2}className="text-center py-2 px-3 w-1/2">Effect</th>
          </tr>
        </thead>
        <tbody>
          {data.annotations && (Object.entries(data.annotations) as Array<[string, {effect: string, attack_model: string}]>).map(([annotationId, annotation]) => (
            <tr key={annotationId} className="hover:bg-indigo-50 dark:hover:bg-indigo-900/20 transition-colors border-t border-gray-200 dark:border-gray-700 group relative">
              <td className="py-1.5 px-3 text-xs dark:text-gray-300">{annotation.attack_model}</td>
              <td className="py-1.5 px-3 text-xs dark:text-gray-300">{annotation.effect}</td>
              <td>
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
              </td>
            </tr>
          ))}
        </tbody>
        <tfoot>
        <tr className="border-t border-gray-200 dark:border-gray-700 bg-gradient-to-b from-transparent to-indigo-50/30 dark:to-indigo-900/10">
            <td className="p-1 relative">
              <input
                type="text"
                placeholder="Attack"
                className={`w-full text-xs p-1.5 pr-10 rounded border border-gray-200 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-300 dark:placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-indigo-400 dark:focus:ring-indigo-500 ${isSubmitting ? 'opacity-50 cursor-not-allowed' : ''}`}
                value={newAttack}
                onChange={(e) => setNewAttack(e.target.value)}
                onClick={(e) => e.stopPropagation()}
                onFocus={() => setAttackFocused(true)}
                onBlur={() => setAttackFocused(false)}
                disabled={isSubmitting}
              />
              {attackFocused && !isSubmitting && (
                <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-300 dark:text-gray-500 pointer-events-none flex items-center opacity-70">
                  <span className="mr-0.5 text-[10px]">tab</span>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M9 18l6-6-6-6"></path>
                  </svg>
                </div>
              )}
            </td>
            <td className="p-1 relative" colSpan={2}>
              <input
                type="text"
                placeholder="Effect"
                className={`w-full text-xs p-1.5 pr-14 rounded border border-gray-200 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-300 dark:placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-indigo-400 dark:focus:ring-indigo-500 ${isSubmitting ? 'opacity-50 cursor-not-allowed' : ''}`}
                value={newEffect}
                onChange={(e) => setNewEffect(e.target.value)}
                onClick={(e) => e.stopPropagation()}
                onFocus={() => setEffectFocused(true)}
                onBlur={() => setEffectFocused(false)}
                onKeyDown={handleEffectKeyDown}
                disabled={isSubmitting}
              />
              {effectFocused && !isSubmitting && (
                <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-300 dark:text-gray-500 pointer-events-none flex items-center opacity-70">
                  <span className="mr-0.5 text-[10px]">return</span>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="9 10 4 15 9 20"></polyline>
                    <path d="M20 4v7a4 4 0 0 1-4 4H4"></path>
                  </svg>
                </div>
              )}
              {isSubmitting && (
                <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                  <svg className="animate-spin h-4 w-4 text-indigo-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                </div>
              )}
            </td>
          </tr>
        </tfoot>
      </table>      
    </div>
  );
}; 