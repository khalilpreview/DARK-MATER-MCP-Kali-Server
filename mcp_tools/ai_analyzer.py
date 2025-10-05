"""
AI Analysis Module for MCP Tools
Provides intelligent analysis of tool outputs using Ollama models
"""

import asyncio
import aiohttp
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class AIAnalyzer:
    """AI-powered analysis of pentesting tool outputs."""
    
    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "llama2"):
        self.ollama_url = ollama_url.rstrip('/')
        self.model = model
        self.session = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def _query_ollama(self, prompt: str, max_tokens: int = 500) -> Optional[str]:
        """Query the Ollama API with a prompt."""
        if not self.session:
            raise RuntimeError("AIAnalyzer must be used as async context manager")
        
        try:
            data = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "temperature": 0.3  # Lower temperature for more focused analysis
                }
            }
            
            async with self.session.post(
                f"{self.ollama_url}/api/generate",
                json=data,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                
                if response.status == 200:
                    result = await response.json()
                    return result.get("response", "").strip()
                else:
                    logger.error(f"Ollama API returned status {response.status}")
                    return None
                    
        except aiohttp.ClientError as e:
            logger.error(f"Failed to query Ollama: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error querying Ollama: {e}")
            return None
    
    async def analyze_job_output(self, job_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a completed job's output and provide insights."""
        try:
            tool_name = job_data.get("tool_name", "unknown")
            target = job_data.get("target", "unknown")
            status = job_data.get("status", "unknown")
            parsed_output = job_data.get("parsed_output", {})
            stdout = job_data.get("stdout", "")
            stderr = job_data.get("stderr", "")
            
            # Create analysis prompt
            prompt = self._build_analysis_prompt(tool_name, target, status, parsed_output, stdout, stderr)
            
            # Get AI analysis
            analysis = await self._query_ollama(prompt, max_tokens=800)
            
            if not analysis:
                return {
                    "success": False,
                    "error": "Failed to get AI analysis from Ollama"
                }
            
            # Parse the analysis for structured insights
            insights = self._parse_analysis_response(analysis)
            
            return {
                "success": True,
                "analysis": analysis,
                "insights": insights,
                "tool": tool_name,
                "target": target,
                "analyzed_at": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing job output: {e}")
            return {
                "success": False,
                "error": f"Analysis failed: {str(e)}"
            }
    
    def _build_analysis_prompt(self, tool_name: str, target: str, status: str, 
                              parsed_output: Dict[str, Any], stdout: str, stderr: str) -> str:
        """Build a comprehensive analysis prompt for the AI model."""
        
        # Truncate long outputs to avoid token limits
        stdout_snippet = stdout[:2000] + "..." if len(stdout) > 2000 else stdout
        stderr_snippet = stderr[:1000] + "..." if len(stderr) > 1000 else stderr
        
        prompt = f"""You are a cybersecurity expert analyzing the output of a penetration testing tool.

Tool: {tool_name}
Target: {target}
Status: {status}

Parsed Output (JSON):
{json.dumps(parsed_output, indent=2)[:1500]}

Raw Output (stdout):
{stdout_snippet}

Errors (stderr):
{stderr_snippet}

Please provide a concise security analysis including:
1. SUMMARY: What was discovered or attempted
2. FINDINGS: Key security findings and vulnerabilities
3. SEVERITY: Risk level (Critical/High/Medium/Low/Info)
4. RECOMMENDATIONS: Next steps for further testing
5. CONTEXT: What this means for the target's security posture

Keep the analysis under 400 words and focus on actionable security insights."""
        
        return prompt
    
    def _parse_analysis_response(self, analysis: str) -> Dict[str, Any]:
        """Parse the AI analysis response into structured insights."""
        insights = {
            "summary": "",
            "findings": [],
            "severity": "Info",
            "recommendations": [],
            "context": ""
        }
        
        try:
            lines = analysis.split('\n')
            current_section = None
            
            for line in lines:
                line = line.strip()
                
                if line.upper().startswith('SUMMARY:'):
                    current_section = 'summary'
                    insights['summary'] = line.replace('SUMMARY:', '').strip()
                elif line.upper().startswith('FINDINGS:'):
                    current_section = 'findings'
                elif line.upper().startswith('SEVERITY:'):
                    current_section = 'severity'
                    severity_text = line.replace('SEVERITY:', '').strip()
                    # Extract severity level
                    for level in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                        if level.lower() in severity_text.lower():
                            insights['severity'] = level
                            break
                elif line.upper().startswith('RECOMMENDATIONS:'):
                    current_section = 'recommendations'
                elif line.upper().startswith('CONTEXT:'):
                    current_section = 'context'
                elif line and current_section:
                    if current_section == 'summary' and not insights['summary']:
                        insights['summary'] = line
                    elif current_section == 'findings' and line.startswith('-'):
                        insights['findings'].append(line[1:].strip())
                    elif current_section == 'recommendations' and line.startswith('-'):
                        insights['recommendations'].append(line[1:].strip())
                    elif current_section == 'context':
                        insights['context'] += line + ' '
            
            # Clean up context
            insights['context'] = insights['context'].strip()
            
        except Exception as e:
            logger.warning(f"Failed to parse analysis response: {e}")
        
        return insights
    
    async def suggest_next_tools(self, job_data: Dict[str, Any], available_tools: List[str]) -> List[Dict[str, Any]]:
        """Suggest next tools to run based on current findings."""
        try:
            tool_name = job_data.get("tool_name", "unknown")
            target = job_data.get("target", "unknown")
            parsed_output = job_data.get("parsed_output", {})
            
            prompt = f"""You are a penetration testing expert. Based on the following scan results, suggest the next 3-5 tools to run for further security assessment.

Current Tool: {tool_name}
Target: {target}
Findings: {json.dumps(parsed_output, indent=2)[:1000]}

Available Tools: {', '.join(available_tools[:20])}

Please suggest tools in this exact format:
TOOL: tool_name
REASON: Brief explanation why this tool should be used next
PRIORITY: High/Medium/Low

Focus on logical progression from reconnaissance to exploitation to post-exploitation."""
            
            response = await self._query_ollama(prompt, max_tokens=400)
            
            if not response:
                return []
            
            suggestions = []
            lines = response.split('\n')
            current_tool = {}
            
            for line in lines:
                line = line.strip()
                if line.startswith('TOOL:'):
                    if current_tool:
                        suggestions.append(current_tool)
                    current_tool = {"tool": line.replace('TOOL:', '').strip()}
                elif line.startswith('REASON:'):
                    current_tool["reason"] = line.replace('REASON:', '').strip()
                elif line.startswith('PRIORITY:'):
                    priority = line.replace('PRIORITY:', '').strip()
                    current_tool["priority"] = priority if priority in ['High', 'Medium', 'Low'] else 'Medium'
            
            if current_tool:
                suggestions.append(current_tool)
            
            # Filter suggestions to only include available tools
            filtered_suggestions = []
            for suggestion in suggestions:
                if suggestion.get("tool") in available_tools:
                    filtered_suggestions.append(suggestion)
            
            return filtered_suggestions[:5]  # Return top 5 suggestions
            
        except Exception as e:
            logger.error(f"Error suggesting next tools: {e}")
            return []
    
    async def generate_executive_summary(self, job_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate an executive summary of multiple job results."""
        try:
            if not job_results:
                return {"success": False, "error": "No job results provided"}
            
            # Summarize the jobs
            tools_used = [job.get("tool_name", "unknown") for job in job_results]
            targets = list(set(job.get("target", "unknown") for job in job_results))
            successful_jobs = [job for job in job_results if job.get("status") == "completed"]
            
            # Create summary prompt
            prompt = f"""Generate an executive summary for a penetration testing engagement.

Tools Used: {', '.join(set(tools_used))}
Targets Tested: {', '.join(targets)}
Total Tests: {len(job_results)}
Successful Tests: {len(successful_jobs)}

Key Findings from completed tests:
"""
            
            # Add findings from each successful job
            for i, job in enumerate(successful_jobs[:5]):  # Limit to top 5 to avoid token limits
                parsed = job.get("parsed_output", {})
                findings_summary = json.dumps(parsed, indent=2)[:300]
                prompt += f"\nTest {i+1} ({job.get('tool_name')}): {findings_summary}\n"
            
            prompt += """
Please provide an executive summary including:
1. OVERVIEW: High-level summary of the testing
2. CRITICAL_FINDINGS: Most important security issues discovered
3. RISK_ASSESSMENT: Overall security posture
4. BUSINESS_IMPACT: Potential impact to the organization
5. RECOMMENDATIONS: Priority remediation steps

Keep the summary professional and suitable for executive leadership."""
            
            summary = await self._query_ollama(prompt, max_tokens=600)
            
            if not summary:
                return {"success": False, "error": "Failed to generate executive summary"}
            
            return {
                "success": True,
                "executive_summary": summary,
                "stats": {
                    "total_tests": len(job_results),
                    "successful_tests": len(successful_jobs),
                    "tools_used": len(set(tools_used)),
                    "targets_tested": len(targets)
                },
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating executive summary: {e}")
            return {"success": False, "error": f"Summary generation failed: {str(e)}"}

# Global analyzer instance
ai_analyzer = None

def get_ai_analyzer(ollama_url: str = "http://localhost:11434", model: str = "llama2") -> AIAnalyzer:
    """Get or create the global AI analyzer instance."""
    global ai_analyzer
    if ai_analyzer is None:
        ai_analyzer = AIAnalyzer(ollama_url=ollama_url, model=model)
    return ai_analyzer