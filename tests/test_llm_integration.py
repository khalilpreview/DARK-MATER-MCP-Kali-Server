"""
Integration tests for the LLM API endpoints.
"""

import pytest
import tempfile
import os
import json
from fastapi.testclient import TestClient

# Mock the database path for testing
os.environ["LLM_DB_PATH"] = tempfile.mktemp(suffix='.db')

from mcp_server.api import app
from mcp_server.auth import generate_enrollment_token

@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)

@pytest.fixture
def api_key(client):
    """Get a valid API key for testing."""
    # Create enrollment
    enrollment_data = {
        "id": "test-server-integration",
        "token": generate_enrollment_token(),
        "label": "Integration Test Server"
    }
    
    # Enroll server
    response = client.post("/enroll", json=enrollment_data)
    assert response.status_code == 200
    data = response.json()
    return data["api_key"]

@pytest.fixture
def headers(api_key):
    """Create authorization headers."""
    return {"Authorization": f"Bearer {api_key}"}

class TestLLMConfigEndpoints:
    """Test LLM configuration endpoints."""
    
    def test_get_default_config(self, client, headers):
        """Test getting default LLM configuration."""
        response = client.get("/llm/config", headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "server_id" in data
        assert "system_prompt" in data
        assert "guardrails" in data
        assert "runtime_hints" in data
        assert "tools_allowed" in data
        assert "etag" in data
        assert "version" in data
    
    def test_update_config(self, client, headers):
        """Test updating LLM configuration."""
        # Get current config
        response = client.get("/llm/config", headers=headers)
        current_config = response.json()
        current_etag = current_config["etag"]
        
        # Update config
        update_data = {
            "system_prompt": "You are a specialized security assistant",
            "guardrails": {
                "disallowed": ["passwords", "secrets"],
                "style": "detailed",
                "max_tokens_hint": 500
            },
            "runtime_hints": {
                "preferred_model": "llama2",
                "temperature": 0.1
            },
            "tools_allowed": ["nmap", "nikto"]
        }
        
        response = client.put(
            "/llm/config", 
            json=update_data,
            headers={**headers, "If-Match": current_etag}
        )
        assert response.status_code == 200
        
        updated_config = response.json()
        assert updated_config["system_prompt"] == update_data["system_prompt"]
        assert updated_config["guardrails"] == update_data["guardrails"]
        assert updated_config["etag"] != current_etag  # ETag should change
    
    def test_config_optimistic_concurrency(self, client, headers):
        """Test optimistic concurrency control with ETag."""
        # Get current config
        response = client.get("/llm/config", headers=headers)
        current_config = response.json()
        
        # Try to update with wrong ETag
        update_data = {"system_prompt": "New prompt"}
        response = client.put(
            "/llm/config",
            json=update_data,
            headers={**headers, "If-Match": "wrong-etag"}
        )
        assert response.status_code == 409  # Conflict
    
    def test_get_config_etag(self, client, headers):
        """Test ETag endpoint."""
        response = client.get("/llm/config/etag", headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "etag" in data

class TestKnowledgeEndpoints:
    """Test knowledge management endpoints."""
    
    def test_create_and_manage_documents(self, client, headers):
        """Test document creation and management."""
        # Create document
        doc_data = {
            "title": "SSH Security Guide",
            "source": "manual:ssh",
            "tags": ["ssh", "security", "linux"]
        }
        
        response = client.post("/llm/knowledge/docs", json=doc_data, headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "doc_id" in data
        assert data["title"] == doc_data["title"]
        
        doc_id = data["doc_id"]
        
        # Update document
        update_data = {
            "title": "Updated SSH Guide",
            "source": "manual:ssh-v2",
            "tags": ["ssh", "security", "updated"]
        }
        
        response = client.put(f"/llm/knowledge/docs/{doc_id}", json=update_data, headers=headers)
        assert response.status_code == 200
        
        # Delete document
        response = client.delete(f"/llm/knowledge/docs/{doc_id}", headers=headers)
        assert response.status_code == 200
    
    def test_add_chunks_and_search(self, client, headers):
        """Test adding chunks and searching."""
        # Create document
        response = client.post(
            "/llm/knowledge/docs",
            json={"title": "Network Security", "source": "guide"},
            headers=headers
        )
        doc_id = response.json()["doc_id"]
        
        # Add chunks
        chunks_data = {
            "chunks": [
                "Use nmap to scan for open ports on target systems",
                "Nikto is a web vulnerability scanner for finding security issues",
                "Always get permission before scanning networks",
                "SSH keys are more secure than password authentication"
            ]
        }
        
        response = client.post(
            f"/llm/knowledge/docs/{doc_id}/chunks",
            json=chunks_data,
            headers=headers
        )
        assert response.status_code == 200
        
        data = response.json()
        assert len(data["chunk_ids"]) == len(chunks_data["chunks"])
        
        # Search knowledge
        response = client.get(
            "/llm/knowledge/search",
            params={"q": "nmap scan ports", "top_k": 3},
            headers=headers
        )
        assert response.status_code == 200
        
        search_results = response.json()
        assert "query" in search_results
        assert "results" in search_results
        assert len(search_results["results"]) > 0
        
        # Should find nmap-related content
        found_nmap = any("nmap" in result["text"].lower() for result in search_results["results"])
        assert found_nmap
    
    def test_reindex_knowledge(self, client, headers):
        """Test knowledge reindexing."""
        response = client.post("/llm/knowledge/reindex", headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "reindexed" in data
        assert "server_id" in data

class TestMemoryEndpoints:
    """Test memory management endpoints."""
    
    def test_append_and_retrieve_memory(self, client, headers):
        """Test complete memory workflow."""
        thread_id = "test-thread-123"
        
        # Append user message
        append_data = {
            "thread_id": thread_id,
            "role": "user",
            "content": "How do I scan a network with nmap?",
            "meta": {"ip": "192.168.1.100", "timestamp": "2025-10-05T10:00:00Z"}
        }
        
        response = client.post("/memory/append", json=append_data, headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert data["thread_id"] == thread_id
        assert "memory_id" in data
        
        # Append assistant response
        assistant_data = {
            "thread_id": thread_id,
            "role": "assistant",
            "content": "You can use 'nmap -sV target' to scan for services and versions.",
            "meta": {"tool_used": "nmap"}
        }
        
        response = client.post("/memory/append", json=assistant_data, headers=headers)
        assert response.status_code == 200
        
        # Retrieve memory
        response = client.get(
            "/memory/retrieve",
            params={"thread_id": thread_id, "limit": 10},
            headers=headers
        )
        assert response.status_code == 200
        
        memory_data = response.json()
        assert memory_data["thread_id"] == thread_id
        assert len(memory_data["turns"]) == 2
        
        turns = memory_data["turns"]
        assert turns[0]["role"] == "user"
        assert turns[0]["content"] == append_data["content"]
        assert turns[1]["role"] == "assistant"
        
        # Retrieve with semantic query
        response = client.get(
            "/memory/retrieve",
            params={"thread_id": thread_id, "q": "network scanning", "limit": 5},
            headers=headers
        )
        assert response.status_code == 200
        
        semantic_data = response.json()
        assert "snippets" in semantic_data
    
    def test_memory_summarization(self, client, headers):
        """Test memory summarization."""
        thread_id = "test-thread-summary"
        
        # Add several conversation turns
        for i in range(5):
            role = "user" if i % 2 == 0 else "assistant"
            content = f"Message {i} about network security"
            
            append_data = {
                "thread_id": thread_id,
                "role": role,
                "content": content
            }
            
            response = client.post("/memory/append", json=append_data, headers=headers)
            assert response.status_code == 200
        
        # Summarize conversation
        summary_data = {
            "thread_id": thread_id,
            "summary": "User asked about network security best practices. Discussed nmap scanning, SSH hardening, and firewall configuration."
        }
        
        response = client.post("/memory/summarize", json=summary_data, headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert data["thread_id"] == thread_id
        assert "summary_id" in data

class TestLiveContextEndpoint:
    """Test live context endpoint."""
    
    def test_get_live_context(self, client, headers):
        """Test getting live server context."""
        response = client.get("/llm/context", headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "server_id" in data
        assert "uptime" in data
        assert "alerts" in data
        assert "services" in data
        assert "disk_usage" in data
        
        # Alerts should be a list
        assert isinstance(data["alerts"], list)
        
        # Services should be a list with proper structure
        assert isinstance(data["services"], list)

class TestJWTAuthentication:
    """Test JWT token authentication."""
    
    def test_create_jwt_token(self, client, api_key):
        """Test JWT token creation."""
        token_request = {
            "api_key": api_key
        }
        
        response = client.post("/auth/token", json=token_request)
        assert response.status_code == 200
        
        data = response.json()
        assert "access_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
        assert "server_id" in data
    
    def test_invalid_api_key_for_token(self, client):
        """Test JWT token creation with invalid API key."""
        token_request = {
            "api_key": "invalid-key-12345"
        }
        
        response = client.post("/auth/token", json=token_request)
        assert response.status_code == 401

class TestFullIntegrationWorkflow:
    """Test complete integration workflow."""
    
    def test_complete_llm_workflow(self, client, headers):
        """Test the complete LLM system workflow."""
        thread_id = "integration-workflow-test"
        
        # 1. Configure LLM
        config_data = {
            "system_prompt": "You are a security testing assistant",
            "tools_allowed": ["nmap", "nikto"]
        }
        response = client.put("/llm/config", json=config_data, headers=headers)
        assert response.status_code == 200
        
        # 2. Add knowledge
        doc_response = client.post(
            "/llm/knowledge/docs",
            json={"title": "Scanning Guide", "source": "manual"},
            headers=headers
        )
        doc_id = doc_response.json()["doc_id"]
        
        chunks_response = client.post(
            f"/llm/knowledge/docs/{doc_id}/chunks",
            json={"chunks": ["Use nmap -sV for version detection"]},
            headers=headers
        )
        assert chunks_response.status_code == 200
        
        # 3. Start conversation
        client.post(
            "/memory/append",
            json={
                "thread_id": thread_id,
                "role": "user",
                "content": "How do I detect service versions?"
            },
            headers=headers
        )
        
        # 4. Search knowledge for context
        search_response = client.get(
            "/llm/knowledge/search",
            params={"q": "version detection", "top_k": 3},
            headers=headers
        )
        knowledge_results = search_response.json()
        assert len(knowledge_results["results"]) > 0
        
        # 5. Add assistant response with context
        client.post(
            "/memory/append",
            json={
                "thread_id": thread_id,
                "role": "assistant",
                "content": "Based on the scanning guide, use nmap -sV for version detection",
                "meta": {"used_knowledge": True}
            },
            headers=headers
        )
        
        # 6. Retrieve full conversation
        memory_response = client.get(
            "/memory/retrieve",
            params={"thread_id": thread_id, "q": "version detection"},
            headers=headers
        )
        memory_data = memory_response.json()
        
        assert len(memory_data["turns"]) == 2
        assert len(memory_data["snippets"]) > 0  # Should have knowledge snippets
        
        # 7. Get live context
        context_response = client.get("/llm/context", headers=headers)
        assert context_response.status_code == 200
        
        # 8. Summarize conversation
        summary_response = client.post(
            "/memory/summarize",
            json={
                "thread_id": thread_id,
                "summary": "User asked about version detection, provided nmap guidance"
            },
            headers=headers
        )
        assert summary_response.status_code == 200

if __name__ == "__main__":
    pytest.main([__file__, "-v"])