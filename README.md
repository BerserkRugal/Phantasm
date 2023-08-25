# PHANTASM: Adaptive Scalable Mining toward Stable BlockDAG

PHANTASM is implemented based on the Github repository provided by phantom's authors: https://github.com/AvivYaish/PHANTOM.

PHANTASM reconstructs the algorithm for selecting previous blocks by implementing an adaptive scalable mining method, allowing for the use of block reference strategies to affect the DAG topology.

This package includes:
- All the packages included by PHANTOM
- Two concrete block reference strategies for Phantom to construct PHANTASM
    - Max cumulative score (PHANTOM_CumulativeScore)
    - Longest shortest path (PHANTOM_ShortestPath)
- An implementation of a splitting attack against the PHANTOM protocol.

### Installation
There are two methods of installation:
- Download the repository and run: 

        cd PHANTOM_CumulativeScore
        pip install .

- Download the repository and run: 

        cd PHANTOM_CumulativeScore
        python setup.py install  

### Usage
There are two ways to run the simulation:
1. Using run_simulation.py to run a single simulation:
        
        cd PHANTOM_CumulativeScore
        python -m phantom.network_simulation.run_simulation

2. Using analyze_attack_success_rate.py to run multiple simulations on various combinations of run-time parameters to analyze the success rate of a given attack on given block-DAG protocols.
        
        cd PHANTOM_CumulativeScore
        python -m phantom.network_simulation.analyze_attack_success_rate

All parameters relevant for each run method are contained in the run script and can easily be changed.
