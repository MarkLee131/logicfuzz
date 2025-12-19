"""
Bias: 用于 API 选择的随机策略
"""
import random
from typing import List


class Bias:
    """
    简单的随机选择策略（可扩展为更复杂的 bias 策略）
    """
    
    def __init__(self):
        pass 
    
    def get_random_candidate(self, driver, candidate_api):
        """
        从候选 API 列表中随机选择一个
        
        Args:
            driver: 当前 driver（未使用，保留接口兼容性）
            candidate_api: 候选 API 列表
        
        Returns:
            随机选择的 API
        """
        if not candidate_api:
            raise ValueError("candidate_api cannot be empty")
        return random.choice(candidate_api)

