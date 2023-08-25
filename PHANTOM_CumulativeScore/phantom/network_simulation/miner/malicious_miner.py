import uuid
from collections import deque

from typing import Deque
from phantom.dag import Block, MaliciousDAG
from .miner import Miner


class MaliciousMiner(Miner):
    """
    A malicious miner on the network.
    """

    def __init__(self, name: Miner.Name,
                 dag: MaliciousDAG,
                 max_peer_num: float,
                 block_size: Block.BlockSize,
                 fetch_requested_blocks: bool = False,
                 broadcast_added_blocks: bool = False
                 ):
        super().__init__(name, dag, max_peer_num, block_size, fetch_requested_blocks, broadcast_added_blocks)
        self._blocks_to_broadcast_queue: Deque[Block] = deque()

    def _broadcast_malicious_block(self, block: Block):
        """
        Broadcasts a malicious block.
        """
        self._network.add_block(block)
        self._blocks_to_broadcast_queue.append(block)
        self._broadcast_block_queue()

    def _broadcast_block_queue(self):
        """
        Broadcasts all selfish blocks if possible.
        """
        attack_success = self._dag.did_attack_succeed()
        if self._dag.did_attack_fail() or attack_success:
            while self._blocks_to_broadcast_queue:
                self._network.broadcast_block(self._name, self._blocks_to_broadcast_queue.pop())
            if attack_success:
                self._network.attack_success()
                self._network._simulation._log("attacked gid is: " + str(self._dag._currently_attacked_block_gid) +
                                               ", malicious depth is: " + str(self._dag.get_depth(self._dag._currently_attacked_block_gid)) +
                                               ", honest dag depth is: " + str(self._dag._honest_dag.get_depth(self._dag._currently_attacked_block_gid)))
                self._network._simulation._log("parallel gid is: " + str(self._dag._first_parallel_block_gid) +
                                               ", malicious depth is: " + str(self._dag.get_depth(self._dag._first_parallel_block_gid)) +
                                               ", honest dag depth is: " + str(self._dag._honest_dag.get_depth(self._dag._first_parallel_block_gid)))

    def add_block(self, block: Block) -> bool:
        addition_success = super().add_block(block)
        self._broadcast_block_queue()   # every new block might influence that attack's status (success/failure)
        return addition_success

    def mine_block(self) -> Block:
        # gid = hash(uuid.uuid4().int)
        gid = self._network.get_next_global_id()

        candidates = self._dag.get_virtual_block_parents(is_malicious=True)
        selected_parents, cum_score = self.compute_score(candidates)

        block = Block(global_id=gid,
                      # parents=self._dag.get_virtual_block_parents(is_malicious=True).copy(),
                      parents=selected_parents.copy(),
                      size=self._block_size,  # assume for the simulation's purposes that blocks are maximal
                      data=self._name,  # use the data field to hold the miner's name for better logs
                      score=cum_score)
        self._dag.add(block, is_malicious=True)
        self._broadcast_malicious_block(block)
        self._mined_blocks_gids.add(gid)
        return block
