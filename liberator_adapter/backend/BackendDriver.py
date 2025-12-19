"""
BackendDriver: 抽象基类，定义 driver 代码生成的接口
"""
from typing import List, Set, Dict, Tuple, Optional
from abc import ABC, abstractmethod


class BackendDriver(ABC):
    """
    BackendDriver 抽象基类：定义 driver 代码生成的接口
    
    子类需要实现：
    - get_name(): 生成 driver 文件名
    - emit_driver(): 生成 driver 代码文件
    - emit_seeds(): 生成初始种子文件
    """

    @abstractmethod
    def __init__(self, working_dir, seeds_dir, num_seeds):
        """
        初始化 BackendDriver
        
        Args:
            working_dir: driver 代码输出目录
            seeds_dir: 种子文件输出目录
            num_seeds: 每个 driver 的种子数量
        """
        pass

    @abstractmethod
    def get_name(self) -> str:
        """
        生成下一个 driver 的文件名
        
        Returns:
            driver 文件名（如 "driver0.cc"）
        """
        pass

    @abstractmethod
    def emit_driver(self, driver, driver_filename):
        """
        生成 driver 代码文件
        
        Args:
            driver: Driver 对象
            driver_filename: 输出文件名
        """
        pass

    @abstractmethod
    def emit_seeds(self, driver, driver_filename):
        """
        生成初始种子文件
        
        Args:
            driver: Driver 对象
            driver_filename: driver 文件名（用于创建对应的种子目录）
        """
        pass

