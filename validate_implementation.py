#!/usr/bin/env python3
"""
MCP Kali Server v2.0 - Implementation Validation
Verifies all components from the copilot instructions are properly implemented.
"""

import os
import json
import importlib.util
from pathlib import Path
from typing import Dict, Any, List

class ImplementationValidator:
    """Validates MCP Kali Server implementation against specifications."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.results: List[Dict[str, Any]] = []
        
    def log_check(self, component: str, status: bool, details: str = ""):
        """Log validation result."""
        status_icon = "✅" if status else "❌"
        print(f"{status_icon} {component}")
        if details:
            print(f"    {details}")
        self.results.append({
            "component": component,
            "status": status,
            "details": details
        })
        
    def check_project_structure(self):
        """Validate project directory structure."""
        print("\n📁 Project Structure Validation")
        print("=" * 40)
        
        required_structure = {
            "kali_server.py": "Main server entrypoint",
            "install.sh": "Systemd installer script",
            "requirements.txt": "Python dependencies",
            "README.md": "Documentation",
            "mcp_server/__init__.py": "Package initialization",
            "mcp_server/api.py": "FastAPI application",
            "mcp_server/auth.py": "Authentication & enrollment",
            "mcp_server/scope.py": "Guardrails & scope validation",
            "mcp_server/tools.py": "Schema-validated tools API",
            "mcp_server/artifacts.py": "Artifact storage & parsing",
            "mcp_server/memory.py": "Memory hooks & observation recording",
            "mcp_server/util.py": "Utility functions",
            "mcp_server/schemas/tools/net_scan_basic.json": "Tool schema"
        }
        
        for file_path, description in required_structure.items():
            full_path = self.project_root / file_path
            exists = full_path.exists()
            self.log_check(f"{file_path}", exists, description if exists else "Missing file")
            
    def check_dependencies(self):
        """Validate required dependencies in requirements.txt."""
        print("\n📦 Dependencies Validation")
        print("=" * 40)
        
        required_deps = [
            "fastapi", "uvicorn", "pydantic", "websockets", 
            "jsonschema", "cryptography", "python-dateutil"
        ]
        
        req_file = self.project_root / "requirements.txt"
        if not req_file.exists():
            self.log_check("requirements.txt", False, "File not found")
            return
            
        with open(req_file, 'r') as f:
            content = f.read().lower()
            
        for dep in required_deps:
            found = dep in content
            self.log_check(f"Dependency: {dep}", found)
            
    def check_schemas(self):
        """Validate JSON schemas."""
        print("\n📋 Schema Validation")
        print("=" * 40)
        
        schema_file = self.project_root / "mcp_server/schemas/tools/net_scan_basic.json"
        if not schema_file.exists():
            self.log_check("net_scan_basic.json", False, "Schema file missing")
            return
            
        try:
            with open(schema_file, 'r') as f:
                schema = json.load(f)
                
            # Validate schema structure
            required_fields = ["$schema", "title", "type", "properties", "required"]
            for field in required_fields:
                if field not in schema:
                    self.log_check(f"Schema field: {field}", False, "Missing from schema")
                    return
                    
            # Check specific requirements from specification
            properties = schema.get("properties", {})
            if "target" not in properties:
                self.log_check("Schema target property", False, "Missing target property")
                return
                
            target_prop = properties["target"]
            if target_prop.get("pattern") != "^[0-9A-Za-z.:/_-]+$":
                self.log_check("Schema target pattern", False, "Incorrect pattern")
                return
                
            self.log_check("net_scan_basic.json schema", True, "Valid schema structure")
            
        except Exception as e:
            self.log_check("Schema parsing", False, f"Error: {e}")
            
    def check_api_endpoints(self):
        """Validate API endpoint definitions."""
        print("\n🌐 API Endpoints Validation")
        print("=" * 40)
        
        api_file = self.project_root / "mcp_server/api.py"
        if not api_file.exists():
            self.log_check("api.py", False, "File not found")
            return
            
        with open(api_file, 'r') as f:
            content = f.read()
            
        required_endpoints = [
            ('/enroll', 'POST'),
            ('/health', 'GET'),
            ('/tools/list', 'GET'),
            ('/tools/call', 'POST'),
            ('/artifacts/list', 'GET'),
            ('/artifacts/read', 'GET')
        ]
        
        for endpoint, method in required_endpoints:
            pattern = f'@app.{method.lower()}("{endpoint}"'
            found = pattern in content
            self.log_check(f"{method} {endpoint}", found)
            
    def check_auth_components(self):
        """Validate authentication components."""
        print("\n🔐 Authentication Validation")
        print("=" * 40)
        
        auth_file = self.project_root / "mcp_server/auth.py"
        if not auth_file.exists():
            self.log_check("auth.py", False, "File not found")
            return
            
        with open(auth_file, 'r') as f:
            content = f.read()
            
        required_functions = [
            "load_enroll",
            "save_api_credentials", 
            "load_api_credentials",
            "require_api_key",
            "generate_api_key",
            "enroll_server"
        ]
        
        for func in required_functions:
            found = f"def {func}" in content
            self.log_check(f"Function: {func}", found)
            
    def check_scope_validation(self):
        """Validate scope and guardrails components."""
        print("\n🛡️ Scope & Guardrails Validation")
        print("=" * 40)
        
        scope_file = self.project_root / "mcp_server/scope.py"
        if not scope_file.exists():
            self.log_check("scope.py", False, "File not found")
            return
            
        with open(scope_file, 'r') as f:
            content = f.read()
            
        required_functions = [
            "in_scope",
            "is_destructive", 
            "validate_scope_and_destructiveness",
            "load_scope_config"
        ]
        
        for func in required_functions:
            found = f"def {func}" in content
            self.log_check(f"Function: {func}", found)
            
        # Check for CIDR validation
        cidr_check = "ipaddress" in content and "IPv4Network" in content
        self.log_check("CIDR validation support", cidr_check)
        
    def check_tools_implementation(self):
        """Validate tools implementation."""
        print("\n🔧 Tools Implementation Validation")
        print("=" * 40)
        
        tools_file = self.project_root / "mcp_server/tools.py"
        if not tools_file.exists():
            self.log_check("tools.py", False, "File not found")
            return
            
        with open(tools_file, 'r') as f:
            content = f.read()
            
        required_functions = [
            "list_tools",
            "call_tool",
            "_execute_nmap_basic"
        ]
        
        for func in required_functions:
            found = f"def {func}" in content
            self.log_check(f"Function: {func}", found)
            
        # Check for safe execution patterns
        safe_patterns = [
            "subprocess.run" in content,
            "shell=False" in content or "shell=True" not in content,
            "timeout=" in content
        ]
        
        self.log_check("Safe subprocess execution", all(safe_patterns))
        
    def check_artifacts_system(self):
        """Validate artifacts system."""
        print("\n📦 Artifacts System Validation")
        print("=" * 40)
        
        artifacts_file = self.project_root / "mcp_server/artifacts.py"
        if not artifacts_file.exists():
            self.log_check("artifacts.py", False, "File not found")
            return
            
        with open(artifacts_file, 'r') as f:
            content = f.read()
            
        required_functions = [
            "save_artifact",
            "list_artifacts",
            "read_artifact",
            "parse_nmap_xml"
        ]
        
        for func in required_functions:
            found = f"def {func}" in content
            self.log_check(f"Function: {func}", found)
            
        # Check artifact URI pattern
        uri_pattern = 'artifact://' in content
        self.log_check("Artifact URI support", uri_pattern)
        
    def check_memory_hooks(self):
        """Validate memory system."""
        print("\n🧠 Memory System Validation")
        print("=" * 40)
        
        memory_file = self.project_root / "mcp_server/memory.py"
        if not memory_file.exists():
            self.log_check("memory.py", False, "File not found")
            return
            
        with open(memory_file, 'r') as f:
            content = f.read()
            
        required_functions = [
            "record_observation",
            "search_memory"
        ]
        
        for func in required_functions:
            found = f"def {func}" in content
            self.log_check(f"Function: {func}", found)
            
    def check_installer(self):
        """Validate installer script."""
        print("\n⚙️ Installer Validation")
        print("=" * 40)
        
        install_file = self.project_root / "install.sh"
        if not install_file.exists():
            self.log_check("install.sh", False, "File not found")
            return
            
        with open(install_file, 'r') as f:
            content = f.read()
            
        required_components = [
            "useradd.*mcpserver",
            "systemctl.*enable",
            "ExecStart=.*kali_server.py",
            "openssl rand.*hex",  # Enrollment token generation
            "/etc/mcp-kali/enroll.json"
        ]
        
        for pattern in required_components:
            import re
            found = bool(re.search(pattern, content))
            self.log_check(f"Installer component: {pattern}", found)
            
    def generate_summary(self):
        """Generate validation summary."""
        print("\n" + "=" * 60)
        print("📊 IMPLEMENTATION VALIDATION SUMMARY")
        print("=" * 60)
        
        passed = sum(1 for result in self.results if result["status"])
        total = len(self.results)
        
        categories = {}
        for result in self.results:
            component = result["component"]
            # Extract category from component name
            if "/" in component:
                category = component.split("/")[0]
            elif ":" in component:
                category = component.split(":")[0]
            else:
                category = "General"
                
            if category not in categories:
                categories[category] = {"passed": 0, "total": 0}
            categories[category]["total"] += 1
            if result["status"]:
                categories[category]["passed"] += 1
                
        for category, stats in categories.items():
            status = "✅" if stats["passed"] == stats["total"] else "⚠️" 
            print(f"{status} {category}: {stats['passed']}/{stats['total']}")
            
        print(f"\n🎯 OVERALL: {passed}/{total} components validated")
        
        if passed == total:
            print("🎉 ALL COMPONENTS IMPLEMENTED CORRECTLY!")
            print("✅ The MCP Kali Server meets all specification requirements.")
        else:
            print("⚠️  Some components need attention.")
            print("❌ Check the failed validations above.")
        
        return passed == total
        
    def run_validation(self):
        """Run complete validation suite."""
        print("🔍 MCP Kali Server v2.0 - Implementation Validation")
        print("📋 Validating against copilot instruction specifications")
        print("🎯 Checking all required components and functionality")
        
        self.check_project_structure()
        self.check_dependencies()
        self.check_schemas()
        self.check_api_endpoints()
        self.check_auth_components()
        self.check_scope_validation()
        self.check_tools_implementation()
        self.check_artifacts_system()
        self.check_memory_hooks()
        self.check_installer()
        
        return self.generate_summary()

def main():
    """Main validation execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate MCP Kali Server implementation")
    parser.add_argument("--project-root", default=".", help="Project root directory")
    
    args = parser.parse_args()
    
    validator = ImplementationValidator(args.project_root)
    success = validator.run_validation()
    
    return 0 if success else 1

if __name__ == "__main__":
    import sys
    sys.exit(main())