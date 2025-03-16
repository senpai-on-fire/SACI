import { AnnotationId, ComponentId, Annotation, Connection } from '../types';

export function groupAnnotationsByComponentId(annotations: {[id: AnnotationId]: Annotation} | undefined) {    
  if (!annotations) return {};

  // Group annotations by attack_surface
  const groupedAnnotations: {
    [attack_surface: ComponentId]: {
      [id: AnnotationId]: {
        effect: string;
        attack_model: string;
      }
    }
  } = {};
    
  // Iterate through each annotation and group by attack_surface
  Object.entries(annotations).forEach(([id, annotation]) => {
    const { attack_surface, effect, attack_model } = annotation;
    
    // Initialize the attack surface group if it doesn't exist
    if (!groupedAnnotations[attack_surface]) {
      groupedAnnotations[attack_surface] = {};
    }
    
    // Add the annotation to its attack surface group
    groupedAnnotations[attack_surface][parseInt(id)] = {
      effect,
      attack_model
    };
  });
    
  return groupedAnnotations;
}

export function adjacencyListOfComponentIds(connections: Connection[]) {
  const adjacencyList: {[id: ComponentId]: ComponentId[]} = {};

  connections.forEach(([from, to]) => {
    if (!adjacencyList[from]) adjacencyList[from] = [];
    adjacencyList[from].push(to);
  });

  return adjacencyList;
}