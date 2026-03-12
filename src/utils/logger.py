"""
Unified logging system for LangGraph workflows.
Eliminates duplicate logging and provides clean, structured logs.

This system provides:
1. Human-readable text logs for easy review
2. Structured JSON logs for programmatic analysis
3. Token usage tracking
4. Metadata capture (model, temperature, etc.)
"""

import os
import json
import threading
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path

import logger  # Import project-level logger for finalize() method


class LangGraphLogger:
    """
    Unified logger for LangGraph workflows that eliminates duplicate logging.
    
    Good taste principles:
    1. One logger per workflow, not per agent
    2. Batch writes to avoid file I/O spam  
    3. Simple directory structure: logs/workflow_id/agent_name/
    4. Only log when explicitly requested, not every interaction
    """

    _instances: Dict[str, 'LangGraphLogger'] = {}
    _lock = threading.Lock()

    def __init__(self,
                 workflow_id: str,
                 trial: int,
                 base_dir: Optional[str] = None):
        self.workflow_id = workflow_id
        self.trial = trial

        # If base_dir is provided, use it directly (e.g., output-xxx directory)
        # Otherwise, use the old default for backward compatibility
        if base_dir:
            self.base_dir = Path(base_dir)
            self.log_dir = self.base_dir / "logs" / f"trial_{trial:02d}"
        else:
            # Fallback for backward compatibility
            self.base_dir = Path("results/logs")
            self.log_dir = self.base_dir / f"trial_{trial:02d}"

        # Ensure directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Per-agent log buffers to batch writes
        self._buffers: Dict[str, List[str]] = {}
        self._json_buffers: Dict[str, List[Dict[str, Any]]] = {}
        # Use RLock (reentrant lock) instead of Lock to allow same thread to acquire it multiple times
        # This fixes deadlock in finalize() -> flush_agent_logs() where both try to acquire the lock
        self._buffer_lock = threading.RLock()

        # Token usage tracking
        self._token_stats: Dict[str, Dict[str, int]] = {}

        # Note: Cannot use self.info() here as it's not yet initialized
        # This initialization message can be logged after the instance is created if needed

    @classmethod
    def get_logger(cls,
                   workflow_id: str,
                   trial: int,
                   base_dir: Optional[str] = None) -> 'LangGraphLogger':
        """
        Get or create logger instance for this workflow.
        
        Args:
            workflow_id: Unique workflow identifier
            trial: Trial number
            base_dir: Base directory for logs (e.g., output-xxx directory).
                     If provided, logs will be stored in base_dir/logs/trial_XX/
                     If not provided, uses results/logs/trial_XX/ for backward compatibility
        """
        key = f"{workflow_id}_{trial}"

        with cls._lock:
            if key not in cls._instances:
                cls._instances[key] = cls(workflow_id, trial, base_dir)
            return cls._instances[key]

    def log_interaction(self,
                        agent_name: str,
                        interaction_type: str,
                        content: str,
                        round_num: int = 1,
                        metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a single LLM interaction in both text and JSON formats.
        
        Args:
            agent_name: Name of the agent (e.g., 'FunctionAnalyzer')
            interaction_type: Type of interaction ('prompt', 'response', 'tool_call')
            content: The actual content to log
            round_num: Round number for this interaction
            metadata: Optional metadata (model, temperature, tokens, etc.)
        """
        if not content or not content.strip():
            return

        timestamp = datetime.now()
        timestamp_str = timestamp.strftime("%H:%M:%S")
        iso_timestamp = timestamp.isoformat()

        # Create human-readable text entry
        text_entry = (
            f"=== {interaction_type.upper()} ROUND {round_num:02d} [{timestamp_str}] ===\n"
        )

        # Add metadata if present
        if metadata:
            text_entry += f"Metadata: {json.dumps(metadata, indent=2)}\n"
            text_entry += "-" * 60 + "\n"

        text_entry += f"{content}\n"
        text_entry += f"{'=' * 80}\n\n"

        # Create structured JSON entry
        json_entry = {
            "timestamp": iso_timestamp,
            "agent": agent_name,
            "round": round_num,
            "type": interaction_type,
            "content": content,
            "metadata": metadata or {}
        }

        # Add to buffers
        with self._buffer_lock:
            if agent_name not in self._buffers:
                self._buffers[agent_name] = []
                self._json_buffers[agent_name] = []

            self._buffers[agent_name].append(text_entry)
            self._json_buffers[agent_name].append(json_entry)

            # Track token usage if present
            if metadata and 'tokens' in metadata:
                if agent_name not in self._token_stats:
                    self._token_stats[agent_name] = {
                        'prompt_tokens': 0,
                        'completion_tokens': 0,
                        'total_tokens': 0,
                        'num_calls': 0
                    }

                tokens = metadata['tokens']
                self._token_stats[agent_name]['prompt_tokens'] += tokens.get(
                    'prompt_tokens', 0)
                self._token_stats[agent_name][
                    'completion_tokens'] += tokens.get('completion_tokens', 0)
                self._token_stats[agent_name]['total_tokens'] += tokens.get(
                    'total_tokens', 0)
                self._token_stats[agent_name]['num_calls'] += 1

    def flush_agent_logs(self, agent_name: str) -> None:
        """Flush all buffered logs for an agent to disk (both text and JSON)."""
        with self._buffer_lock:
            if agent_name not in self._buffers or not self._buffers[agent_name]:
                logger.debug(
                    f'No logs to flush for {agent_name} (buffer empty or doesn\'t exist)',
                    trial=self.trial)
                return

            num_entries = len(self._buffers[agent_name])
            logger.info(
                f'💾 Flushing {num_entries} log entries for {agent_name}...',
                trial=self.trial)

            # Write text log
            agent_log_file = self.log_dir / f"{agent_name.lower()}.log"
            try:
                with open(agent_log_file, 'a', encoding='utf-8') as f:
                    f.writelines(self._buffers[agent_name])

                logger.info(
                    f'✅ Saved text logs for {agent_name}:\n'
                    f'   File: {agent_log_file}\n'
                    f'   Size: {agent_log_file.stat().st_size} bytes\n'
                    f'   Entries: {num_entries}',
                    trial=self.trial)
            except Exception as e:
                logger.error(
                    f'❌ Failed to flush text logs for {agent_name}: {e}',
                    trial=self.trial)

            # Write JSON log (one JSON object per line for easy parsing)
            json_log_file = self.log_dir / f"{agent_name.lower()}.jsonl"
            try:
                num_json_entries = len(self._json_buffers.get(agent_name, []))
                with open(json_log_file, 'a', encoding='utf-8') as f:
                    for entry in self._json_buffers.get(agent_name, []):
                        f.write(json.dumps(entry) + '\n')

                logger.info(
                    f'✅ Saved JSON logs for {agent_name}:\n'
                    f'   File: {json_log_file}\n'
                    f'   Size: {json_log_file.stat().st_size} bytes\n'
                    f'   Entries: {num_json_entries}',
                    trial=self.trial)
            except Exception as e:
                logger.error(
                    f'❌ Failed to flush JSON logs for {agent_name}: {e}',
                    trial=self.trial)

            # Clear the buffers
            self._buffers[agent_name] = []
            if agent_name in self._json_buffers:
                self._json_buffers[agent_name] = []

    def log_workflow_event(self,
                           event_type: str,
                           message: str,
                           metadata: Optional[Dict[str, Any]] = None) -> None:
        """Log workflow-level events (state transitions, errors, etc.)"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        workflow_log = self.log_dir / "workflow.log"

        try:
            with open(workflow_log, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {event_type}: {message}\n")
                if metadata:
                    f.write(f"  Metadata: {metadata}\n")
                f.write("\n")
        except Exception as e:
            logger.warning(f'Failed to log workflow event: {e}',
                           trial=self.trial)

    def get_token_stats(self,
                        agent_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get token usage statistics.
        
        Args:
            agent_name: If provided, return stats for specific agent. 
                       Otherwise return all stats.
        
        Returns:
            Dictionary of token statistics
        """
        with self._buffer_lock:
            if agent_name:
                return self._token_stats.get(agent_name, {})
            return self._token_stats.copy()

    def finalize(self) -> None:
        """Flush all remaining logs, write summary stats, and clean up."""
        import time

        logger.info(
            '🔚 Finalizing LangGraph logger - flushing all remaining logs...',
            trial=self.trial)
        finalize_start = time.time()

        logger.info('📍 [finalize] Acquiring buffer lock...', trial=self.trial)
        lock_start = time.time()
        with self._buffer_lock:
            lock_duration = time.time() - lock_start
            logger.info(
                f'📍 [finalize] Buffer lock acquired in {lock_duration:.3f}s',
                trial=self.trial)

            # Flush all agent logs
            agents_to_flush = list(self._buffers.keys())
            logger.info(
                f'📍 [finalize] Agents to flush: {", ".join(agents_to_flush) if agents_to_flush else "none"}',
                trial=self.trial)

            for i, agent_name in enumerate(agents_to_flush, 1):
                logger.info(
                    f'📍 [finalize] Flushing agent {i}/{len(agents_to_flush)}: {agent_name}...',
                    trial=self.trial)
                flush_start = time.time()
                self.flush_agent_logs(agent_name)
                flush_duration = time.time() - flush_start
                logger.info(
                    f'📍 [finalize] Agent {agent_name} flushed in {flush_duration:.3f}s',
                    trial=self.trial)

            # Write token usage summary
            if self._token_stats:
                logger.info('📍 [finalize] Writing token stats...',
                            trial=self.trial)
                stats_file = self.log_dir / "token_stats.json"
                try:
                    write_start = time.time()
                    with open(stats_file, 'w', encoding='utf-8') as f:
                        json.dump(self._token_stats, f, indent=2)
                    write_duration = time.time() - write_start
                    logger.info(
                        f'📍 [finalize] Token stats written in {write_duration:.3f}s: {stats_file}',
                        trial=self.trial)
                except Exception as e:
                    logger.warning(
                        f'📍 [finalize] Failed to write token stats: {e}',
                        trial=self.trial)
            else:
                logger.info('📍 [finalize] No token stats to write',
                            trial=self.trial)

        finalize_duration = time.time() - finalize_start
        logger.info(
            f'✅ LangGraph logger finalized in {finalize_duration:.3f}s: {self.log_dir}',
            trial=self.trial)


class NullLogger:
    """
    Null object pattern for logging - avoids checking if logger exists.
    
    Implements same interface as LangGraphLogger but does nothing.
    Used when enable_detailed_logging=False.
    """

    def log_interaction(self, *args, **kwargs) -> None:
        pass

    def log_token_usage(self, *args, **kwargs) -> None:
        pass

    def flush_agent_logs(self, *args, **kwargs) -> None:
        pass

    def finalize(self) -> None:
        pass
