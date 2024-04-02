# Orchestrator

Orchestrator orchestrates a CPV discovery and verification process.
It involves the following basic steps:

1. [**Input**] Ingest components and their descriptions of a CPS.
1. [**Input**] Ingest a CPS vulnerability and CPV model database.
1. [**Processing**] Construct a model of the CPS. 
1. [**Discovery**] For each CPV model, find if the CPV may exist on the CPS model with the help of `identifier`.
A path through the CPS model will be identified. The path describes how data moves from the final component (e.g., an acturator) to input components (e.g., a cyber component). 
1. [**Constraining**] For each CPV model that Orchestrator deems to possibly exist, attempt to generate a full CPV input.
1. [**Verification**] Verify each CPV input on the simulation, which is then customized based on what individual CPV input requires.
