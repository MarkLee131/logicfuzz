"""
Bias: Random strategy for API selection
"""
import random
from typing import List


class Bias:
    """
    Simple random selection strategy (can be extended to more complex bias strategies)
    """
    
    def __init__(self):
        pass 
    
    def get_random_candidate(self, driver, candidate_api):
        """
        Randomly select one from candidate API list
        
        Args:
            driver: Current driver (unused, kept for interface compatibility)
            candidate_api: Candidate API list
        
        Returns:
            Randomly selected API
        """
        if not candidate_api:
            raise ValueError("candidate_api cannot be empty")
        return random.choice(candidate_api)

