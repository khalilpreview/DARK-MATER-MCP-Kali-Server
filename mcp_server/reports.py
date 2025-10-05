"""
Report generation system for MCP Kali Server.
Generates comprehensive security assessment reports in multiple formats.
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from enum import Enum
import base64

logger = logging.getLogger(__name__)

class ReportFormat(str, Enum):
    """Supported report formats."""
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"

class ReportTemplate(str, Enum):
    """Report templates."""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAILED = "technical_detailed"
    COMPLIANCE = "compliance"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"

class ReportConfig(BaseModel):
    """Report generation configuration."""
    title: str
    template: ReportTemplate
    format: ReportFormat
    include_raw_data: bool = False
    include_screenshots: bool = False
    severity_filter: Optional[List[str]] = None  # ["high", "critical"]
    max_findings: Optional[int] = None

class ReportData(BaseModel):
    """Data structure for report generation."""
    metadata: Dict[str, Any]
    scan_results: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    statistics: Dict[str, Any]
    timeline: List[Dict[str, Any]]

class ReportGenerator:
    """Generates security assessment reports."""
    
    def __init__(self):
        # Platform-appropriate reports directory
        import os
        if os.name == 'nt':  # Windows
            self.reports_dir = Path.home() / ".mcp-kali" / "reports"
        else:  # Linux/Unix
            self.reports_dir = Path("/var/lib/mcp/reports")
        
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.templates_dir = Path(__file__).parent / "templates"
    
    async def generate_report(self, server_id: str, config: ReportConfig, 
                            scan_ids: List[str] = None, 
                            date_range: tuple = None) -> Dict[str, Any]:
        """
        Generate a comprehensive security report.
        
        Args:
            server_id: Server ID for data filtering
            config: Report generation configuration
            scan_ids: Specific scan IDs to include (optional)
            date_range: Date range tuple (start, end) for filtering
            
        Returns:
            Dictionary with report information and file path
        """
        try:
            # Collect report data
            report_data = await self._collect_report_data(
                server_id, scan_ids, date_range, config
            )
            
            # Generate report based on format
            if config.format == ReportFormat.HTML:
                report_path = await self._generate_html_report(config, report_data)
            elif config.format == ReportFormat.PDF:
                report_path = await self._generate_pdf_report(config, report_data)
            elif config.format == ReportFormat.JSON:
                report_path = await self._generate_json_report(config, report_data)
            elif config.format == ReportFormat.CSV:
                report_path = await self._generate_csv_report(config, report_data)
            else:
                raise ValueError(f"Unsupported report format: {config.format}")
            
            # Calculate report statistics
            stats = self._calculate_report_stats(report_data)
            
            return {
                "report_path": str(report_path),
                "format": config.format.value,
                "template": config.template.value,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "statistics": stats,
                "file_size": report_path.stat().st_size if report_path.exists() else 0
            }
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            raise
    
    async def _collect_report_data(self, server_id: str, scan_ids: List[str], 
                                 date_range: tuple, config: ReportConfig) -> ReportData:
        """Collect data for report generation."""
        try:
            from .memory import memory_manager
            from .artifacts import artifact_manager
            
            # Set default date range if not provided
            if not date_range:
                end_date = datetime.now(timezone.utc)
                start_date = end_date - timedelta(days=30)
                date_range = (start_date, end_date)
            
            # Collect scan results from memory
            observations = await memory_manager.search_memory(
                server_id=server_id,
                start_time=date_range[0],
                end_time=date_range[1],
                limit=1000
            )
            
            scan_results = observations.get("observations", [])
            
            # Filter by scan IDs if provided
            if scan_ids:
                scan_results = [
                    result for result in scan_results
                    if result.get("artifact_uri", "").split("/")[-2] in scan_ids
                ]
            
            # Collect findings and apply filters
            all_findings = []
            for result in scan_results:
                findings = result.get("parsed", {}).get("findings", [])
                
                # Apply severity filter
                if config.severity_filter:
                    findings = [
                        f for f in findings 
                        if f.get("severity", "").lower() in [s.lower() for s in config.severity_filter]
                    ]
                
                all_findings.extend(findings)
            
            # Apply max findings limit
            if config.max_findings and len(all_findings) > config.max_findings:
                # Sort by severity and take top findings
                severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5))
                all_findings = all_findings[:config.max_findings]
            
            # Generate metadata
            metadata = {
                "report_title": config.title,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "server_id": server_id,
                "date_range": {
                    "start": date_range[0].isoformat(),
                    "end": date_range[1].isoformat()
                },
                "scan_count": len(scan_results),
                "findings_count": len(all_findings)
            }
            
            # Calculate statistics
            statistics = self._calculate_statistics(all_findings, scan_results)
            
            # Generate timeline
            timeline = self._generate_timeline(scan_results)
            
            return ReportData(
                metadata=metadata,
                scan_results=scan_results,
                findings=all_findings,
                statistics=statistics,
                timeline=timeline
            )
            
        except Exception as e:
            logger.error(f"Error collecting report data: {e}")
            raise
    
    def _calculate_statistics(self, findings: List[Dict[str, Any]], 
                            scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate report statistics."""
        try:
            # Severity distribution
            severity_counts = {}
            for finding in findings:
                severity = finding.get("severity", "unknown").lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Tool usage statistics
            tool_counts = {}
            for result in scan_results:
                tool_name = result.get("summary", "").split()[0]  # Extract tool name
                tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1
            
            # Risk assessment
            critical_count = severity_counts.get("critical", 0)
            high_count = severity_counts.get("high", 0)
            medium_count = severity_counts.get("medium", 0)
            
            if critical_count > 0:
                risk_level = "Critical"
            elif high_count > 5:
                risk_level = "High"
            elif high_count > 0 or medium_count > 10:
                risk_level = "Medium"
            else:
                risk_level = "Low"
            
            return {
                "total_findings": len(findings),
                "severity_distribution": severity_counts,
                "tool_usage": tool_counts,
                "risk_level": risk_level,
                "scan_coverage": {
                    "total_scans": len(scan_results),
                    "unique_targets": len(set(r.get("target", "") for r in scan_results))
                }
            }
            
        except Exception as e:
            logger.error(f"Error calculating statistics: {e}")
            return {}
    
    def _generate_timeline(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate timeline of security activities."""
        timeline = []
        
        try:
            for result in scan_results:
                timeline_entry = {
                    "timestamp": result.get("timestamp", ""),
                    "event": "scan_completed",
                    "tool": result.get("summary", "").split()[0],
                    "target": result.get("target", "unknown"),
                    "findings_count": len(result.get("parsed", {}).get("findings", []))
                }
                timeline.append(timeline_entry)
            
            # Sort by timestamp
            timeline.sort(key=lambda x: x.get("timestamp", ""))
            
        except Exception as e:
            logger.error(f"Error generating timeline: {e}")
        
        return timeline
    
    async def _generate_html_report(self, config: ReportConfig, data: ReportData) -> Path:
        """Generate HTML format report."""
        try:
            # Generate HTML content
            html_content = self._build_html_report(config, data)
            
            # Save to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.html"
            report_path = self.reports_dir / filename
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Generated HTML report: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            raise
    
    def _build_html_report(self, config: ReportConfig, data: ReportData) -> str:
        """Build HTML report content."""
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{data.metadata['report_title']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; margin-bottom: 30px; }}
                .section {{ margin-bottom: 30px; }}
                .finding {{ border-left: 4px solid #e74c3c; padding: 15px; margin: 10px 0; background: #f8f9fa; }}
                .finding.high {{ border-left-color: #e74c3c; }}
                .finding.medium {{ border-left-color: #f39c12; }}
                .finding.low {{ border-left-color: #27ae60; }}
                .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat-box {{ text-align: center; padding: 20px; background: #ecf0f1; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #34495e; color: white; }}
                .severity-critical {{ color: #e74c3c; font-weight: bold; }}
                .severity-high {{ color: #e67e22; font-weight: bold; }}
                .severity-medium {{ color: #f39c12; }}
                .severity-low {{ color: #27ae60; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔰 {data.metadata['report_title']}</h1>
                <p>Generated: {datetime.fromisoformat(data.metadata['generated_at']).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p>Server ID: {data.metadata['server_id']}</p>
                <p>Risk Level: <span class="severity-{data.statistics.get('risk_level', 'low').lower()}">{data.statistics.get('risk_level', 'Unknown')}</span></p>
            </div>
            
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <div class="stats">
                    <div class="stat-box">
                        <h3>{data.statistics.get('total_findings', 0)}</h3>
                        <p>Total Findings</p>
                    </div>
                    <div class="stat-box">
                        <h3>{data.statistics.get('severity_distribution', {}).get('critical', 0)}</h3>
                        <p>Critical Issues</p>
                    </div>
                    <div class="stat-box">
                        <h3>{data.statistics.get('severity_distribution', {}).get('high', 0)}</h3>
                        <p>High Risk</p>
                    </div>
                    <div class="stat-box">
                        <h3>{data.statistics.get('scan_coverage', {}).get('total_scans', 0)}</h3>
                        <p>Scans Performed</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>🔍 Findings Summary</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Finding</th>
                            <th>Host/Target</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_findings_table_rows(data.findings[:50])}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>📈 Tool Usage</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Tool</th>
                            <th>Usage Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_tool_usage_rows(data.statistics.get('tool_usage', {}))}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>📋 Recommendations</h2>
                {self._generate_recommendations(data.statistics)}
            </div>
            
            <div class="section">
                <h2>📅 Timeline</h2>
                {self._generate_timeline_html(data.timeline[:20])}
            </div>
            
            <footer style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #7f8c8d;">
                <p>Generated by DARK MATTER MCP Kali Server v2.0</p>
                <p>Report contains {len(data.findings)} findings from {len(data.scan_results)} security scans</p>
            </footer>
        </body>
        </html>
        """
        
        return html_template
    
    def _generate_findings_table_rows(self, findings: List[Dict[str, Any]]) -> str:
        """Generate HTML table rows for findings."""
        rows = []
        for finding in findings:
            severity = finding.get("severity", "unknown").lower()
            host = finding.get("host", "") or finding.get("target", "")
            description = finding.get("description", "") or finding.get("vulnerability", "")
            
            rows.append(f"""
                <tr>
                    <td class="severity-{severity}">{severity.title()}</td>
                    <td>{finding.get("vulnerability", "") or finding.get("type", "")}</td>
                    <td>{host}</td>
                    <td>{description[:200]}{'...' if len(description) > 200 else ''}</td>
                </tr>
            """)
        
        return "".join(rows)
    
    def _generate_tool_usage_rows(self, tool_usage: Dict[str, int]) -> str:
        """Generate HTML table rows for tool usage."""
        rows = []
        for tool, count in sorted(tool_usage.items(), key=lambda x: x[1], reverse=True):
            rows.append(f"""
                <tr>
                    <td>{tool}</td>
                    <td>{count}</td>
                </tr>
            """)
        
        return "".join(rows)
    
    def _generate_recommendations(self, statistics: Dict[str, Any]) -> str:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        critical_count = statistics.get("severity_distribution", {}).get("critical", 0)
        high_count = statistics.get("severity_distribution", {}).get("high", 0)
        
        if critical_count > 0:
            recommendations.append(
                "<div class='finding critical'><strong>IMMEDIATE ACTION REQUIRED:</strong> "
                f"{critical_count} critical vulnerabilities found. Address immediately.</div>"
            )
        
        if high_count > 0:
            recommendations.append(
                "<div class='finding high'><strong>HIGH PRIORITY:</strong> "
                f"{high_count} high-risk vulnerabilities require prompt attention.</div>"
            )
        
        if not recommendations:
            recommendations.append(
                "<div class='finding low'><strong>Good Security Posture:</strong> "
                "No critical or high-risk vulnerabilities identified in this assessment.</div>"
            )
        
        return "".join(recommendations)
    
    def _generate_timeline_html(self, timeline: List[Dict[str, Any]]) -> str:
        """Generate HTML timeline."""
        timeline_html = "<div class='timeline'>"
        
        for entry in timeline:
            timeline_html += f"""
                <div style="margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 5px;">
                    <strong>{entry.get('timestamp', '')}</strong> - 
                    {entry.get('tool', '')} scan of {entry.get('target', '')} 
                    ({entry.get('findings_count', 0)} findings)
                </div>
            """
        
        timeline_html += "</div>"
        return timeline_html
    
    async def _generate_json_report(self, config: ReportConfig, data: ReportData) -> Path:
        """Generate JSON format report."""
        try:
            # Create JSON report
            json_report = {
                "metadata": data.metadata,
                "statistics": data.statistics,
                "findings": data.findings,
                "scan_results": data.scan_results if config.include_raw_data else [],
                "timeline": data.timeline
            }
            
            # Save to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.json"
            report_path = self.reports_dir / filename
            
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2, default=str)
            
            logger.info(f"Generated JSON report: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            raise
    
    async def _generate_csv_report(self, config: ReportConfig, data: ReportData) -> Path:
        """Generate CSV format report."""
        try:
            import csv
            
            # Save to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_findings_{timestamp}.csv"
            report_path = self.reports_dir / filename
            
            with open(report_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['severity', 'vulnerability', 'host', 'port', 'description', 'tool']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for finding in data.findings:
                    writer.writerow({
                        'severity': finding.get('severity', ''),
                        'vulnerability': finding.get('vulnerability', '') or finding.get('type', ''),
                        'host': finding.get('host', '') or finding.get('target', ''),
                        'port': finding.get('port', ''),
                        'description': finding.get('description', ''),
                        'tool': finding.get('tool_name', '')
                    })
            
            logger.info(f"Generated CSV report: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
            raise
    
    async def _generate_pdf_report(self, config: ReportConfig, data: ReportData) -> Path:
        """Generate PDF format report (requires weasyprint)."""
        try:
            # First generate HTML
            html_content = self._build_html_report(config, data)
            
            # Convert to PDF using weasyprint (if available)
            try:
                from weasyprint import HTML
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"security_report_{timestamp}.pdf"
                report_path = self.reports_dir / filename
                
                HTML(string=html_content).write_pdf(str(report_path))
                
                logger.info(f"Generated PDF report: {report_path}")
                return report_path
                
            except ImportError:
                logger.warning("weasyprint not available, generating HTML instead of PDF")
                return await self._generate_html_report(config, data)
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            raise
    
    def _calculate_report_stats(self, data: ReportData) -> Dict[str, Any]:
        """Calculate final report statistics."""
        return {
            "total_findings": len(data.findings),
            "total_scans": len(data.scan_results),
            "severity_breakdown": data.statistics.get("severity_distribution", {}),
            "risk_level": data.statistics.get("risk_level", "Unknown")
        }

# Global report generator instance
report_generator = ReportGenerator()

async def generate_security_report(server_id: str, config: ReportConfig, 
                                 scan_ids: List[str] = None) -> Dict[str, Any]:
    """Generate a comprehensive security report."""
    return await report_generator.generate_report(server_id, config, scan_ids)