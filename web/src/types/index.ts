// Common types used across components

export type Component = {
  name: string,
  parameters?: {[name: string]: string | number | boolean | null},
};

export type Connection = [from: ComponentId, to: ComponentId];

export type Device = {
  name: string,
  components: {[name: string]: Component},
  connections: Connection[],
  hypotheses?: {[id: HypothesisId]: Hypothesis},
  annotations?: {[id: AnnotationId]: Annotation}
};

export type Annotation = {
  attack_surface: ComponentId,
  effect: string,
  attack_model: string
}

export type Hypothesis = {
  name: string,
  path: ComponentId[],
  annotations: AnnotationId[]
};

export type AnnotationId = number;
export type BlueprintId = string;
export type ComponentId = number;
export type HypothesisId = number;
