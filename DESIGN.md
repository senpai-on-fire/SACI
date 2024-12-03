# Modeling

## Abstraction Levels

- [x] are treated as a lattice
- represent the different levels of detail needed for different components in a given analysis
- [ ] have a global set encompassing all of them, but each component may only support a subset, so if a given abstraction level desired is unsupported, it will take the next highest/lowest element on the lattice from that it does support

## Components

- [x] can have subcomponents that vary depending on the abstraction level under study
- [x] can have connections that vary depending on the abstraction level under study
- [x] have an identifier that is unique within a device
- [x] have a component type
- [ ] have simulation code associated with them for each abstraction level

## Connections

- [x] are between two components
- [ ] have some sort of description of what the connection is
- [ ] can be multiple between the same two components

## CPVs

- [x] have a set of required component types
- [ ] can require a component to have a specific CPSV

## CPSVs

- [ ] describe a vulnerability in a specific component
- [ ] can either query properties about a component or describe simulations/tests/analyses that must be done to confirm its presence (if said property is not there)

# Analysis

## CPVs

- [x] can be searched for using purely graph search
