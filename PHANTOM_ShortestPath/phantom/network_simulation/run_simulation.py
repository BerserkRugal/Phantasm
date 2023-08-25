"""
A simple run script to run the simulation a single time.
"""
import numpy

from typing import Callable, Iterable, Tuple, List

from phantom.phantom import GreedyPHANTOM, CompetingChainGreedyPHANTOM
from phantom.network_simulation import Simulation

# Default block size in bytes.
DEFAULT_BLOCK_SIZE = 1 << 20

# The default max neighbor num
DEFAULT_MAX_PEER_NUM = 2


def greedy_constructor_with_parameters(k) -> Callable[..., GreedyPHANTOM]:
    """
    :return: a callable constructor with no parameters such that the given
    parameters are "baked-in" as its parameters.
    """

    def to_return() -> GreedyPHANTOM:
        return GreedyPHANTOM(k=k)

    return to_return


def competing_chain_constructor_with_parameters(k, confirmation_depth, maximal_depth_difference) \
        -> Callable[..., CompetingChainGreedyPHANTOM]:
    """
    :return: a callable constructor with no parameters such that the given
    parameters are "baked-in" as its parameters.
    """

    def to_return() -> CompetingChainGreedyPHANTOM:
        return CompetingChainGreedyPHANTOM(k=k,
                                           confirmation_depth=confirmation_depth,
                                           maximal_depth_difference=maximal_depth_difference)

    return to_return


def calculate_hash_rate(hash_ratio: float, other_hash_rates: Iterable[float]) -> float:
    """

    :param hash_ratio:
    :param other_hash_rates:
    :return:
    """
    return sum(other_hash_rates) * hash_ratio / (1 - hash_ratio)


def generate_hash_rates(hash_rate_parameter: int, number_of_honest_miners: int, malicious_hash_ratio: float) -> \
        Tuple[List[float], List[float]]:
    """

    :param number_of_honest_miners:
    :param malicious_hash_ratio:
    :return:
    """
    honest_hash_rates = [numpy.random.poisson(hash_rate_parameter) for i in range(number_of_honest_miners)]
    malicious_hash_rates = [calculate_hash_rate(malicious_hash_ratio, honest_hash_rates)]
    return honest_hash_rates, malicious_hash_rates


def run_simulation() -> Simulation:
    """
    Runs the simulation.
    :return: if the attack succeeded.
    """

    malicious_hash_ratio = 0.45
    number_of_honest_miners = 5
    hash_rate_parameter = 5
    honest_hash_rates, malicious_hash_rates = generate_hash_rates(hash_rate_parameter, number_of_honest_miners,
                                                                  malicious_hash_ratio)
    maximal_depth_difference = round(confirmation_depth * malicious_hash_ratio) + 1

    # simulation runs long enough for 3 attack attempts (actually much more, because the maximal
    # depth difference for the malicious miner is at most 1/2 of the confirmation depth)
    simulation_length = round(confirmation_depth * 3 * 60 / blocks_per_minute)

    # all time-related parameters are in seconds
    simulation = Simulation(honest_hash_rates=honest_hash_rates,
                            malicious_hash_rates=malicious_hash_rates,
                            block_creation_rate=blocks_per_minute * 60,
                            propagation_delay_parameter=30,  # propagation delay is at most 30 seconds
                            security_parameter=0.1,
                            simulation_length=simulation_length,
                            honest_dag_init=greedy_constructor_with_parameters(k),
                            malicious_dag_init=competing_chain_constructor_with_parameters(
                                k=k,
                                confirmation_depth=confirmation_depth,
                                maximal_depth_difference=maximal_depth_difference),
                            median_speed=DEFAULT_BLOCK_SIZE / 2,
                            max_block_size=DEFAULT_BLOCK_SIZE,
                            max_peer_number=DEFAULT_MAX_PEER_NUM,
                            fetch_requested_blocks=False,
                            broadcast_added_blocks=True,
                            no_delay_for_malicious_miners=True,
                            completely_connected_malicious_miners=True,
                            simulate_miner_join_leave=False,
                            enable_printing=False,
                            enable_logging=False,
                            save_simulation=False)
    return simulation


blocks_per_minute = 1.0
k = 13
confirmation_depth = 100


if __name__ == '__main1__':
    sim = run_simulation()
    sim.run()
    print("total blocks: " + str(len(sim._network["M6"]._dag)) + ", coloring ratio: " +
          str(len(sim._network["M6"]._dag._get_coloring()) / len(sim._network["M6"]._dag)) +
          ", blocks per minute: " + str(len(sim._network["M6"]._dag._get_coloring())/sim._env.now*60))


if __name__ == '__main__':
    import time
    total_count = 1000
    attack_count = 0
    blocks_count = 0
    ratio_count = 0
    process_count = 0
    start = time.clock()
    for i in range(total_count):
        sim = run_simulation()
        ret = sim.run()
        blocks_count += len(sim._network["M6"]._dag)
        ratio_count += len(sim._network["M6"]._dag._get_coloring()) / len(sim._network["M6"]._dag)
        process_count += len(sim._network["M6"]._dag._get_coloring()) / sim._env.now * 60
        print("tested count: " + str(i + 1) + ", result: " + str(ret))
        if ret == True:
            attack_count += 1
    end = time.clock()
    print("time cost: " + str(round(end - start,2)) + " seconds, " +
          "attack success probability: " + str(attack_count / total_count * 100) + "%")
    print("average total blocks: " + str(int(blocks_count/total_count)) +
          ", average coloring ratio: " + str(ratio_count/total_count) +
          ", average colored blocks per minute: " + str(process_count/total_count))
    print("shortest ---> k=" + str(k) + ", bpm=" + str(blocks_per_minute) + ", depth=" + str(confirmation_depth))
