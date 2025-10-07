# MCP Kali Server - Demos

This directory contains demonstration scripts and examples for the DARK MATER MCP Kali Server.

## Available Demos

### 🔐 Authentication and Configuration

- **`demo_credentials.py`** - Display server credentials and authentication information
  - Shows API keys, server IDs, and configuration details
  - Provides ready-to-use curl and PowerShell commands
  - Useful for initial setup verification

### 📊 Server Monitoring and Logging

- **`demo_monitored_server.py`** - Start server with comprehensive monitoring
  - Detailed logging configuration
  - Real-time monitoring of API calls
  - Performance tracking and error reporting

- **`demo_simple_server.py`** - Start server with basic logging (Windows compatible)
  - Clean output without Unicode characters
  - Basic monitoring suitable for production
  - Error handling and graceful shutdown

- **`demo_logs.py`** - Comprehensive logging demonstration
  - Background server startup with monitoring
  - Automated test requests to generate logs
  - Real-time log analysis and monitoring

### 🤖 LLM Integration

- **`demo_llm_config.py`** - LLM configuration and integration examples
  - Configuration management demonstration
  - Knowledge base integration examples
  - Memory system usage patterns

- **`demo_logging.py`** - Advanced logging system demonstration
  - Multi-level logging configuration
  - Log formatting and filtering examples
  - Integration with monitoring systems

## Usage Examples

### Quick Server Start with Monitoring
```bash
# Start server with comprehensive monitoring
python demos/demo_monitored_server.py

# Or use the simple Windows-compatible version
python demos/demo_simple_server.py
```

### View Authentication Details
```bash
# Display all authentication information
python demos/demo_credentials.py
```

### Test LLM Integration
```bash
# Demonstrate LLM configuration
python demos/demo_llm_config.py
```

### Advanced Logging Demo
```bash
# Run comprehensive logging demonstration
python demos/demo_logs.py
```

## Integration with Main Server

These demos can be used alongside the main server (`kali_server.py`) or independently for testing and development purposes.

### Production Usage
For production deployments, use the main server entry point:
```bash
python kali_server.py --bind 0.0.0.0:5000
```

### Development and Testing
For development and testing, use the demo scripts to understand specific features:
```bash
python demos/demo_monitored_server.py  # Development monitoring
python demos/demo_credentials.py       # Check authentication setup
```

## Demo Script Features

All demo scripts include:
- ✅ **Error Handling** - Graceful error handling and recovery
- ✅ **Documentation** - Inline documentation and usage examples
- ✅ **Logging** - Appropriate logging levels and output
- ✅ **Testing** - Built-in test functionality where applicable
- ✅ **Windows Compatibility** - Tested on Windows environments

## Contributing

When adding new demo scripts:
1. Follow the naming convention: `demo_feature_name.py`
2. Include comprehensive docstrings and comments
3. Add error handling and logging
4. Update this README with usage examples
5. Test on Windows and Linux environments

## Support

For questions about the demo scripts or the MCP Kali Server:
- Check the main project README
- Review the API documentation
- Run the comprehensive test suite: `python tests/run_tests.py`