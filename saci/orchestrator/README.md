# Orchestrator

Orchestrator orchestrates a CPV discovery and verification process.
It involves the following basic steps:

1. [**Input**] Ingest components and their descriptions of a CPS.
1. [**Input**] Ingest a CPS vulnerability and CPV model database.
1. [**Processing**] Construct a model of the CPS. 
1. [**Discovery**] For each CPV model, find if the CPV exists on the CPS model with the help of `identifier`.
1. [**Discovery**] For each CPV model that Orchestrator deems to exist, attempt to generate a full CPV input.
1. [**Verification**] Verify each CPV input on the simulation, which is then customized based on what individual CPV input requires.
