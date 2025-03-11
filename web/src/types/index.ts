// Common types used across components

export type Component = {
  name: string,
  parameters?: {[name: string]: string | number | boolean | null},
};

export type Device = {
  name: string,
  components: {[name: string]: Component},
  connections: [from: string, to: string][],
  hypotheses?: {[id: string]: Hypothesis},
  annotations?: {
    [id: string]: {
      attack_surface: string,
      effect: string,
      attack_model: string
    }
  }
};

export type Hypothesis = {
  name: string,
  path: string[],
  annotations: string[]
};

export type BlueprintId = string;
export type HypothesisId = string;
export type ComponentId = string;