"""
BackendDriver: Abstract base class defining the interface for driver code generation
"""
from typing import List, Set, Dict, Tuple, Optional
from abc import ABC, abstractmethod


class BackendDriver(ABC):
    """
    BackendDriver abstract base class: Defines the interface for driver code generation
    
    Subclasses need to implement:
    - get_name(): Generate driver file name
    - emit_driver(): Generate driver code file
    - emit_seeds(): Generate initial seed files
    """

    @abstractmethod
    def __init__(self, working_dir, seeds_dir, num_seeds):
        """
        Initialize BackendDriver
        
        Args:
            working_dir: Driver code output directory
            seeds_dir: Seed file output directory
            num_seeds: Number of seeds per driver
        """
        pass

    @abstractmethod
    def get_name(self) -> str:
        """
        Generate the next driver's file name
        
        Returns:
            Driver file name (e.g., "driver0.cc")
        """
        pass

    @abstractmethod
    def emit_driver(self, driver, driver_filename):
        """
        Generate driver code file
        
        Args:
            driver: Driver object
            driver_filename: Output file name
        """
        pass

    @abstractmethod
    def emit_seeds(self, driver, driver_filename):
        """
        Generate initial seed files
        
        Args:
            driver: Driver object
            driver_filename: Driver file name (used to create corresponding seed directory)
        """
        pass

