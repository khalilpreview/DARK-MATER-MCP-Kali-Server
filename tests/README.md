# MCP Kali Server - Test Suite

Comprehensive testing framework for the DARK MATER MCP Kali Server v2.0

## Test Structure

The test suite is organized into multiple categories for comprehensive coverage:

```
tests/
├── run_tests.py              # Main test runner (run this first!)
├── unit/                     # Unit tests for individual components
│   ├── test_server.py        # Core server functionality
│   ├── test_schema.py        # JSON schema validation
│   └── test_schema_validation.py  # Schema validation system
├── integration/              # Integration tests for API endpoints
│   ├── test_server_live.py   # Live server testing
│   ├── test_servers.py       # Multi-server testing
│   ├── test_5001.py          # Port-specific testing
│   ├── test_production_api.py        # Production API testing
│   ├── test_production_api_enhanced.py  # Enhanced API testing
│   ├── test_llm_config.py    # LLM configuration testing
│   └── test_llm_config_enhanced.py     # Enhanced LLM testing
├── acceptance/               # End-to-end acceptance tests
│   ├── test_complete_live.py     # Complete system testing
│   └── test_complete_live_enhanced.py  # Enhanced live testing
└── system/                   # System-level tests
    ├── test_llm_integration.py   # LLM system integration
    └── test_llm_system.py        # LLM system functionality
```

## Quick Start

### Run All Tests (Recommended)
```bash
# Run the comprehensive test suite
python tests/run_tests.py
```

This will:
- ✅ Check environment setup
- ✅ Discover all test files
- ✅ Run tests by category (unit → integration → acceptance → system)
- ✅ Generate detailed reports
- ✅ Save results to `test_results.json`

### Run Specific Test Categories

```bash
# Run only unit tests
python tests/unit/test_server.py

# Run only integration tests  
python tests/integration/test_server_live.py

# Run only acceptance tests
python tests/acceptance/test_complete_live_enhanced.py
```

## Test Categories

### 🔬 Unit Tests (`tests/unit/`)
Test individual components in isolation:
- **Core server logic** - Authentication, routing, error handling
- **Schema validation** - JSON schema validation for tool parameters
- **Utility functions** - Helper functions and data processing

### 🔗 Integration Tests (`tests/integration/`)
Test API endpoints and component interactions:
- **API endpoints** - Health checks, tool execution, artifact management
- **Authentication flow** - API key validation and authorization
- **Tool integration** - Security tool execution and result processing
- **LLM integration** - Language model configuration and usage

### ✅ Acceptance Tests (`tests/acceptance/`)
End-to-end testing from user perspective:
- **Complete workflows** - Full penetration testing scenarios
- **Real tool execution** - Actual security tool runs (where safe)
- **Client integration** - Testing with various client configurations

### 🖥️ System Tests (`tests/system/`)
System-level integration and performance testing:
- **Multi-component integration** - LLM + tools + artifacts
- **Performance testing** - Load testing and resource usage
- **Environment validation** - System requirements and dependencies

## Test Runner Features

The main test runner (`run_tests.py`) provides:

### 🔍 Environment Validation
- Python version compatibility (>= 3.8)
- Virtual environment detection
- Required package availability
- Project structure validation

### 📊 Comprehensive Reporting
- Real-time test progress
- Detailed success/failure reporting
- Execution time tracking
- JSON report generation

### 🛡️ Error Handling
- Timeout protection (60s per test)
- Graceful failure handling
- Detailed error logging
- Recovery suggestions

## First Launch Integration

The test suite is automatically executed on first server launch:

1. **First Launch Detection** - Checks for `.setup_completed` marker
2. **Automatic Test Execution** - Runs full test suite
3. **Project Validation** - Ensures all systems are working
4. **Setup Completion** - Marks setup as complete on success

To manually trigger first launch setup:
```bash
python setup_first_launch.py
```

## Test Development Guidelines

### Writing New Tests

1. **Follow naming conventions**: `test_feature_name.py`
2. **Include docstrings**: Document what each test validates
3. **Use proper categories**: Place in appropriate directory
4. **Handle cleanup**: Clean up resources after tests
5. **Test isolation**: Each test should run independently

### Example Test Structure
```python
#!/usr/bin/env python3
"""
Test Description: What this test validates
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_feature():
    """Test specific feature functionality"""
    # Test implementation
    pass

def main():
    """Main test function"""
    try:
        test_feature()
        print("✅ All tests passed")
        return True
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
```

## Continuous Integration

The test suite is designed for CI/CD integration:

- **Exit codes**: 0 for success, 1 for failure
- **JSON reports**: Machine-readable test results
- **Environment checks**: Validates setup before testing
- **Timeout protection**: Prevents hanging in CI environments

## Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Ensure you're in the project root
   cd /path/to/mcp-kali-server
   python tests/run_tests.py
   ```

2. **Missing Dependencies**
   ```bash
   # Install requirements
   pip install -r requirements.txt
   ```

3. **Permission Issues**
   ```bash
   # Ensure scripts are executable
   chmod +x tests/run_tests.py
   ```

### Test Failures

If tests fail:
1. Review the detailed output
2. Check `test_results.json` for specifics
3. Fix underlying issues
4. Re-run tests: `python tests/run_tests.py`

## Performance Benchmarks

Expected test execution times:
- **Unit Tests**: < 10 seconds
- **Integration Tests**: < 30 seconds  
- **Acceptance Tests**: < 60 seconds
- **Full Suite**: < 2 minutes

## Contributing

When contributing tests:
1. Run full test suite before submitting
2. Ensure new tests pass consistently
3. Update this README for new test categories
4. Add appropriate error handling
5. Test on multiple environments

## Support

For test-related issues:
- Check test output and `test_results.json`
- Ensure environment meets requirements
- Review project setup and dependencies
- Contact the development team for persistent issues