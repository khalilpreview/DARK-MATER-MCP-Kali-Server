"""
Tool Manager for MCP Pentesting Tools
Handles tool discovery, validation, execution, and output management.
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import uuid
import yaml
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, AsyncGenerator
import aiofiles

from .parsers import PARSERS, OutputParser
from .ai_analyzer import get_ai_analyzer, AIAnalyzer

logger = logging.getLogger(__name__)

class ToolJob:
    """Represents a running or completed tool execution job."""
    
    def __init__(self, job_id: str, tool_name: str, command: str, target: str, 
                 args: Dict[str, Any], safe_mode: bool = True):
        self.job_id = job_id
        self.tool_name = tool_name
        self.command = command
        self.target = target
        self.args = args
        self.safe_mode = safe_mode
        self.status = "queued"  # queued, running, completed, failed, cancelled
        self.process = None
        self.start_time = None
        self.end_time = None
        self.exit_code = None
        self.stdout = ""
        self.stderr = ""
        self.parsed_output = None
        self.artifacts = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert job to dictionary for serialization."""
        return {
            "job_id": self.job_id,
            "tool_name": self.tool_name,
            "command": self.command,
            "target": self.target,
            "args": self.args,
            "safe_mode": self.safe_mode,
            "status": self.status,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "exit_code": self.exit_code,
            "parsed_output": self.parsed_output,
            "artifacts": self.artifacts
        }

class ToolManager:
    """Manages pentesting tool discovery, validation, and execution."""
    
    def __init__(self, registry_path: Optional[Path] = None, 
                 allowed_targets: Optional[List[str]] = None,
                 force_mode: bool = False):
        self.registry_path = registry_path or Path(__file__).parent / "registry"
        self.allowed_targets = allowed_targets or self._load_allowed_targets()
        self.force_mode = force_mode
        self.tools_registry = {}
        self.active_jobs = {}
        self.completed_jobs = {}
        self.load_tools_registry()
    
    def _load_allowed_targets(self) -> List[str]:
        """Load allowed targets from environment variable."""
        targets_env = os.getenv('ALLOWED_TARGETS', '')
        if targets_env:
            return [t.strip() for t in targets_env.split(',') if t.strip()]
        
        # Default safe targets for testing
        return [
            '127.0.0.1',
            'localhost',
            '10.0.0.0/8',
            '172.16.0.0/12', 
            '192.168.0.0/16'
        ]
    
    def load_tools_registry(self):
        """Load all tool definitions from YAML files."""
        if not self.registry_path.exists():
            logger.error(f"Registry path does not exist: {self.registry_path}")
            return
        
        for yaml_file in self.registry_path.glob("*.yaml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    category_tools = yaml.safe_load(f)
                
                category = yaml_file.stem
                for tool_name, tool_config in category_tools.items():
                    tool_config['category'] = category
                    tool_config['available'] = self._check_tool_availability(tool_name, tool_config)
                    self.tools_registry[tool_name] = tool_config
                
                logger.info(f"Loaded {len(category_tools)} tools from {yaml_file.name}")
                
            except Exception as e:
                logger.error(f"Error loading {yaml_file}: {e}")
        
        logger.info(f"Total tools registered: {len(self.tools_registry)}")
    
    def _check_tool_availability(self, tool_name: str, tool_config: Dict[str, Any]) -> bool:
        """Check if a tool is available on the system."""
        # Check for API-only tools
        if 'api_endpoint' in tool_config and 'exec_command' not in tool_config:
            return True  # API availability checked during execution
        
        # Check for executable availability
        exec_command = tool_config.get('exec_command', '')
        if exec_command:
            # Extract the main command (first word)
            main_command = exec_command.split()[0]
            return shutil.which(main_command) is not None
        
        # Check for tool suites with multiple commands
        if 'tools' in tool_config:
            # Check if at least one tool in the suite is available
            for sub_tool, sub_command in tool_config['tools'].items():
                main_command = sub_command.split()[0]
                if shutil.which(main_command) is not None:
                    return True
            return False
        
        return False
    
    def list_tools(self, category: Optional[str] = None, 
                   available_only: bool = True) -> List[Dict[str, Any]]:
        """List available tools, optionally filtered by category."""
        tools = []
        
        for tool_name, tool_config in self.tools_registry.items():
            if category and tool_config.get('category') != category:
                continue
            
            if available_only and not tool_config.get('available', False):
                continue
            
            tools.append({
                'name': tool_name,
                'category': tool_config.get('category', 'unknown'),
                'description': tool_config.get('description', ''),
                'available': tool_config.get('available', False),
                'requires_root': tool_config.get('requires_root', False),
                'safe_mode_allowed': tool_config.get('safe_mode_allowed', True),
                'timeout': tool_config.get('timeout', 300),
                'has_api': 'api_endpoint' in tool_config
            })
        
        return sorted(tools, key=lambda x: (x['category'], x['name']))
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific tool."""
        return self.tools_registry.get(tool_name)
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is in allowed targets list."""
        if self.force_mode:
            return True
        
        import ipaddress
        
        try:
            target_ip = ipaddress.IPv4Address(target)
        except ipaddress.AddressValueError:
            # Try to resolve hostname
            try:
                import socket
                target_ip = ipaddress.IPv4Address(socket.gethostbyname(target))
            except:
                # Can't resolve, check if it's in allowed list as-is
                return target in self.allowed_targets
        
        # Check against allowed CIDR ranges
        for allowed in self.allowed_targets:
            try:
                if '/' in allowed:
                    network = ipaddress.IPv4Network(allowed, strict=False)
                    if target_ip in network:
                        return True
                else:
                    if str(target_ip) == allowed or target == allowed:
                        return True
            except:
                continue
        
        return False
    
    async def run_tool(self, tool_name: str, target: str, 
                      args: Optional[Dict[str, Any]] = None,
                      safe_mode: bool = True) -> str:
        """Start a tool execution job and return job ID."""
        # Validate tool exists and is available
        tool_config = self.tools_registry.get(tool_name)
        if not tool_config:
            raise ValueError(f"Tool '{tool_name}' not found in registry")
        
        if not tool_config.get('available', False):
            raise ValueError(f"Tool '{tool_name}' is not available on this system")
        
        # Validate target
        if not self.validate_target(target):
            raise ValueError(f"Target '{target}' is not in allowed targets list")
        
        # Check safe mode restrictions
        if safe_mode and not tool_config.get('safe_mode_allowed', True):
            raise ValueError(f"Tool '{tool_name}' is not allowed in safe mode")
        
        # Generate job ID and create job
        job_id = str(uuid.uuid4())
        command = self._build_command(tool_config, target, args or {})
        
        job = ToolJob(
            job_id=job_id,
            tool_name=tool_name,
            command=command,
            target=target,
            args=args or {},
            safe_mode=safe_mode
        )
        
        self.active_jobs[job_id] = job
        
        # Start execution in background
        asyncio.create_task(self._execute_job(job))
        
        return job_id
    
    def _build_command(self, tool_config: Dict[str, Any], target: str, 
                      args: Dict[str, Any]) -> str:
        """Build the command string for tool execution."""
        exec_command = tool_config.get('exec_command', '')
        if not exec_command:
            raise ValueError(f"No execution command defined for tool")
        
        # Replace placeholders
        command = exec_command.format(target=target, **args)
        
        # Add output file if needed
        if '{output_file}' in exec_command and 'output_file' not in args:
            output_file = f"/tmp/{tool_config.get('category', 'tool')}_{uuid.uuid4().hex[:8]}.out"
            command = command.replace('{output_file}', output_file)
        
        return command
    
    async def _execute_job(self, job: ToolJob):
        """Execute a tool job asynchronously."""
        job.status = "running"
        job.start_time = datetime.now(timezone.utc)
        
        try:
            tool_config = self.tools_registry[job.tool_name]
            timeout = tool_config.get('timeout', 300)
            
            # Create subprocess
            process = await asyncio.create_subprocess_shell(
                job.command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024*1024  # 1MB buffer limit
            )
            
            job.process = process
            
            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=timeout
                )
                
                job.stdout = stdout.decode('utf-8', errors='replace')
                job.stderr = stderr.decode('utf-8', errors='replace')
                job.exit_code = process.returncode
                
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                job.status = "failed"
                job.stderr = f"Tool execution timed out after {timeout} seconds"
                job.exit_code = -1
            
            # Parse output if parser is available
            parser_name = tool_config.get('output_parser')
            if parser_name and parser_name in PARSERS:
                try:
                    job.parsed_output = PARSERS[parser_name](job.stdout)
                except Exception as e:
                    logger.error(f"Error parsing output for {job.tool_name}: {e}")
                    job.parsed_output = {"parse_error": str(e), "raw_output": job.stdout}
            
            # Determine final status
            if job.exit_code == 0:
                job.status = "completed"
            else:
                job.status = "failed"
                
        except Exception as e:
            logger.error(f"Error executing job {job.job_id}: {e}")
            job.status = "failed"
            job.stderr = str(e)
            job.exit_code = -1
        
        finally:
            job.end_time = datetime.now(timezone.utc)
            
            # Move to completed jobs
            if job.job_id in self.active_jobs:
                del self.active_jobs[job.job_id]
            self.completed_jobs[job.job_id] = job
            
            # Log to database (will be implemented in next phase)
            await self._log_job_to_db(job)
    
    async def _log_job_to_db(self, job: ToolJob):
        """Log job execution to the observation database."""
        try:
            # Import the existing memory manager
            from mcp_server.memory import memory_manager
            
            # Create observation summary
            summary = f"Tool '{job.tool_name}' executed against {job.target}"
            if job.status == "completed":
                summary += f" - completed successfully in {(job.end_time - job.start_time).total_seconds():.1f}s"
            elif job.status == "failed":
                summary += f" - failed with exit code {job.exit_code}"
            elif job.status == "cancelled":
                summary += " - cancelled by user"
            
            # Prepare parsed data
            parsed_data = {
                "job_id": job.job_id,
                "tool_name": job.tool_name,
                "target": job.target,
                "args": job.args,
                "safe_mode": job.safe_mode,
                "status": job.status,
                "exit_code": job.exit_code,
                "duration": (job.end_time - job.start_time).total_seconds() if job.start_time and job.end_time else None,
                "stdout_lines": len(job.stdout.split('\n')) if job.stdout else 0,
                "stderr_lines": len(job.stderr.split('\n')) if job.stderr else 0,
                "parsed_output": job.parsed_output
            }
            
            # Record observation
            memory_manager.record_observation(
                server_id="tool_manager",  # Use a consistent ID for tool manager
                kind="tool_execution",
                summary=summary,
                parsed=parsed_data
            )
            
            # Also log to existing audit system if available
            try:
                from mcp_server.audit import audit_logger
                audit_logger.log_tool_execution(
                    server_id="tool_manager",
                    tool_name=job.tool_name,
                    target=job.target,
                    success=(job.status == "completed"),
                    job_id=job.job_id,
                    duration=(job.end_time - job.start_time).total_seconds() if job.start_time and job.end_time else None
                )
            except Exception as audit_error:
                logger.warning(f"Failed to log to audit system: {audit_error}")
                
        except Exception as e:
            logger.error(f"Failed to log job to database: {e}")
            # Fallback to simple logging
            log_entry = {
                "timestamp": job.end_time.isoformat() if job.end_time else None,
                "job_id": job.job_id,
                "tool": job.tool_name,
                "target": job.target,
                "exit_code": job.exit_code,
                "status": job.status,
                "duration": (job.end_time - job.start_time).total_seconds() if job.start_time and job.end_time else None
            }
            logger.info(f"Tool execution completed: {log_entry}")
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get the current status of a job."""
        # Check active jobs first
        if job_id in self.active_jobs:
            return self.active_jobs[job_id].to_dict()
        
        # Check completed jobs
        if job_id in self.completed_jobs:
            return self.completed_jobs[job_id].to_dict()
        
        return None
    
    async def stream_job_output(self, job_id: str) -> AsyncGenerator[str, None]:
        """Stream live output from a running job."""
        job = self.active_jobs.get(job_id)
        if not job:
            yield json.dumps({"error": "Job not found or not running"})
            return
        
        if job.status != "running" or not job.process:
            yield json.dumps({"error": "Job is not currently running"})
            return
        
        # Stream stdout
        while job.status == "running" and job.process:
            try:
                # This is a simplified version - real streaming would require
                # more sophisticated buffering and line handling
                await asyncio.sleep(1)
                if job.stdout:
                    yield json.dumps({
                        "type": "stdout",
                        "data": job.stdout[-1000:],  # Last 1000 chars
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
            except Exception as e:
                yield json.dumps({"error": f"Streaming error: {e}"})
                break
    
    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job."""
        job = self.active_jobs.get(job_id)
        if not job or job.status != "running":
            return False
        
        if job.process:
            try:
                job.process.kill()
                job.status = "cancelled"
                return True
            except:
                return False
        
        return False
    
    def get_categories(self) -> List[str]:
        """Get list of available tool categories."""
        categories = set()
        for tool_config in self.tools_registry.values():
            categories.add(tool_config.get('category', 'unknown'))
        return sorted(list(categories))
    
    def cleanup_old_jobs(self, max_age_hours: int = 24):
        """Clean up old completed jobs to free memory."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        
        jobs_to_remove = []
        for job_id, job in self.completed_jobs.items():
            if job.end_time and job.end_time < cutoff_time:
                jobs_to_remove.append(job_id)
        
        for job_id in jobs_to_remove:
            del self.completed_jobs[job_id]
        
        logger.info(f"Cleaned up {len(jobs_to_remove)} old jobs")
    
    async def analyze_job(self, job_id: str, ollama_url: str = "http://localhost:11434", 
                         model: str = "llama2") -> Dict[str, Any]:
        """Analyze a completed job using AI."""
        job = self.completed_jobs.get(job_id)
        if not job:
            raise ValueError(f"Completed job {job_id} not found")
        
        try:
            async with get_ai_analyzer(ollama_url, model) as analyzer:
                job_data = {
                    "job_id": job_id,
                    "tool_name": job.tool_name,
                    "target": job.args.get("target", "unknown"),
                    "status": "completed" if job.return_code == 0 else "failed",
                    "parsed_output": job.parsed_output,
                    "stdout": job.stdout,
                    "stderr": job.stderr,
                    "return_code": job.return_code,
                    "duration": (job.end_time - job.start_time).total_seconds() if job.end_time else None
                }
                
                return await analyzer.analyze_job_output(job_data)
                
        except Exception as e:
            logger.error(f"Error analyzing job {job_id}: {e}")
            return {
                "success": False,
                "error": f"Analysis failed: {str(e)}"
            }
    
    async def suggest_next_tools(self, job_id: str, ollama_url: str = "http://localhost:11434",
                                model: str = "llama2") -> List[Dict[str, Any]]:
        """Get AI suggestions for next tools to run based on current results."""
        job = self.completed_jobs.get(job_id)
        if not job:
            raise ValueError(f"Completed job {job_id} not found")
        
        try:
            available_tools = list(self.tools.keys())
            
            async with get_ai_analyzer(ollama_url, model) as analyzer:
                job_data = {
                    "job_id": job_id,
                    "tool_name": job.tool_name,
                    "target": job.args.get("target", "unknown"),
                    "parsed_output": job.parsed_output,
                    "stdout": job.stdout
                }
                
                return await analyzer.suggest_next_tools(job_data, available_tools)
                
        except Exception as e:
            logger.error(f"Error getting tool suggestions for job {job_id}: {e}")
            return []
    
    async def generate_executive_summary(self, job_ids: List[str] = None, 
                                        ollama_url: str = "http://localhost:11434",
                                        model: str = "llama2") -> Dict[str, Any]:
        """Generate an executive summary of multiple jobs."""
        if job_ids is None:
            # Use all completed jobs
            jobs_to_analyze = list(self.completed_jobs.values())
        else:
            jobs_to_analyze = []
            for job_id in job_ids:
                job = self.completed_jobs.get(job_id)
                if job:
                    jobs_to_analyze.append(job)
        
        if not jobs_to_analyze:
            return {
                "success": False,
                "error": "No completed jobs found to analyze"
            }
        
        try:
            async with get_ai_analyzer(ollama_url, model) as analyzer:
                job_results = []
                for job in jobs_to_analyze:
                    job_data = {
                        "job_id": job.job_id,
                        "tool_name": job.tool_name,
                        "target": job.args.get("target", "unknown"),
                        "status": "completed" if job.return_code == 0 else "failed",
                        "parsed_output": job.parsed_output,
                        "stdout": job.stdout,
                        "stderr": job.stderr,
                        "return_code": job.return_code,
                        "duration": (job.end_time - job.start_time).total_seconds() if job.end_time else None
                    }
                    job_results.append(job_data)
                
                return await analyzer.generate_executive_summary(job_results)
                
        except Exception as e:
            logger.error(f"Error generating executive summary: {e}")
            return {
                "success": False,
                "error": f"Summary generation failed: {str(e)}"
            }

# Global tool manager instance
tool_manager = None

def get_tool_manager(force_mode: bool = False) -> ToolManager:
    """Get or create the global tool manager instance."""
    global tool_manager
    if tool_manager is None:
        tool_manager = ToolManager(force_mode=force_mode)
    return tool_manager