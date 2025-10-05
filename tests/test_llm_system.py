"""
Unit tests for LLM configuration and knowledge management system.
"""

import pytest
import tempfile
import os
from datetime import datetime, timezone

from mcp_server.llm_db import LLMDatabase

@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    
    db = LLMDatabase(db_path)
    yield db
    
    # Cleanup
    os.unlink(db_path)

class TestLLMConfiguration:
    """Test LLM configuration management."""
    
    def test_set_and_get_config(self, temp_db):
        """Test setting and getting LLM configuration."""
        server_id = "test-server-01"
        config = {
            "system_prompt": "You are a test assistant",
            "guardrails": {"disallowed": ["secrets"]},
            "runtime_hints": {"temperature": 0.5},
            "tools_allowed": ["nmap", "nikto"]
        }
        
        # Set configuration
        result = temp_db.set_llm_config(server_id, config)
        
        assert result["server_id"] == server_id
        assert result["system_prompt"] == config["system_prompt"]
        assert result["guardrails"] == config["guardrails"]
        assert result["runtime_hints"] == config["runtime_hints"]
        assert result["tools_allowed"] == config["tools_allowed"]
        assert "etag" in result
        assert "version" in result
        
        # Get configuration
        retrieved = temp_db.get_llm_config(server_id)
        assert retrieved == result
    
    def test_config_etag_generation(self, temp_db):
        """Test ETag generation for configuration caching."""
        server_id = "test-server-02"
        config1 = {"system_prompt": "Prompt 1"}
        config2 = {"system_prompt": "Prompt 2"}
        
        result1 = temp_db.set_llm_config(server_id, config1)
        result2 = temp_db.set_llm_config(server_id, config2)
        
        # ETags should be different for different configurations
        assert result1["etag"] != result2["etag"]
        
        # ETag retrieval should work
        etag = temp_db.get_config_etag(server_id)
        assert etag == result2["etag"]
    
    def test_nonexistent_config(self, temp_db):
        """Test getting configuration for non-existent server."""
        result = temp_db.get_llm_config("nonexistent-server")
        assert result is None
        
        etag = temp_db.get_config_etag("nonexistent-server")
        assert etag is None

class TestKnowledgeManagement:
    """Test knowledge document and search functionality."""
    
    def test_create_and_manage_docs(self, temp_db):
        """Test creating and managing knowledge documents."""
        server_id = "test-server-01"
        
        # Create document
        doc_id = temp_db.create_knowledge_doc(
            server_id, 
            "Test Document", 
            "test-source",
            ["tag1", "tag2"]
        )
        
        assert doc_id is not None
        assert len(doc_id) > 0
        
        # Update document
        success = temp_db.update_knowledge_doc(
            doc_id,
            "Updated Document",
            "updated-source",
            ["tag1", "tag3"]
        )
        assert success is True
        
        # Update non-existent document
        success = temp_db.update_knowledge_doc(
            "non-existent",
            "Title"
        )
        assert success is False
    
    def test_add_and_search_chunks(self, temp_db):
        """Test adding chunks and searching knowledge base."""
        server_id = "test-server-01"
        
        # Create document
        doc_id = temp_db.create_knowledge_doc(
            server_id,
            "SSH Guide",
            "manual:ssh"
        )
        
        # Add chunks
        chunks = [
            "SSH is a secure protocol for remote access",
            "To restart SSH service use systemctl restart ssh",
            "SSH keys provide better security than passwords",
            "Default SSH port is 22 but can be changed"
        ]
        
        chunk_ids = temp_db.add_knowledge_chunks(doc_id, chunks)
        assert len(chunk_ids) == len(chunks)
        
        # Search for chunks
        results = temp_db.search_knowledge(server_id, "restart ssh", top_k=2)
        
        assert "query" in results
        assert "results" in results
        assert results["query"] == "restart ssh"
        assert len(results["results"]) <= 2
        
        # Should find the restart chunk
        found_restart = any("restart" in result["text"].lower() for result in results["results"])
        assert found_restart
        
        # Test search with no results
        no_results = temp_db.search_knowledge(server_id, "nonexistent query xyz", top_k=5)
        assert len(no_results["results"]) == 0
    
    def test_delete_document(self, temp_db):
        """Test deleting documents and cascading chunk deletion."""
        server_id = "test-server-01"
        
        # Create document and add chunks
        doc_id = temp_db.create_knowledge_doc(server_id, "Test Doc")
        temp_db.add_knowledge_chunks(doc_id, ["chunk1", "chunk2"])
        
        # Verify chunks exist
        results = temp_db.search_knowledge(server_id, "chunk1", top_k=5)
        assert len(results["results"]) > 0
        
        # Delete document
        success = temp_db.delete_knowledge_doc(doc_id)
        assert success is True
        
        # Verify chunks are gone
        results = temp_db.search_knowledge(server_id, "chunk1", top_k=5)
        assert len(results["results"]) == 0
        
        # Delete non-existent document
        success = temp_db.delete_knowledge_doc("non-existent")
        assert success is False
    
    def test_reindex_knowledge(self, temp_db):
        """Test knowledge base reindexing."""
        server_id = "test-server-01"
        
        # Create some documents and chunks
        doc_id1 = temp_db.create_knowledge_doc(server_id, "Doc 1")
        doc_id2 = temp_db.create_knowledge_doc(server_id, "Doc 2")
        
        temp_db.add_knowledge_chunks(doc_id1, ["content1", "content2"])
        temp_db.add_knowledge_chunks(doc_id2, ["content3", "content4"])
        
        # Reindex specific server
        count = temp_db.reindex_knowledge(server_id)
        assert count == 4  # 4 chunks total
        
        # Search should still work after reindex
        results = temp_db.search_knowledge(server_id, "content1", top_k=5)
        assert len(results["results"]) > 0

class TestMemoryManagement:
    """Test conversation memory functionality."""
    
    def test_append_and_retrieve_memory(self, temp_db):
        """Test appending and retrieving conversation memory."""
        server_id = "test-server-01"
        thread_id = "thread-abc"
        
        # Append some conversation turns
        id1 = temp_db.append_memory(server_id, thread_id, "user", "Hello", {"ip": "192.168.1.1"})
        id2 = temp_db.append_memory(server_id, thread_id, "assistant", "Hi there!", {})
        id3 = temp_db.append_memory(server_id, thread_id, "user", "What is SSH?", {})
        
        assert id1 > 0
        assert id2 > 0
        assert id3 > 0
        
        # Retrieve memory
        result = temp_db.retrieve_memory(server_id, thread_id, limit=5)
        
        assert result["thread_id"] == thread_id
        assert len(result["turns"]) == 3
        
        # Should be in chronological order
        turns = result["turns"]
        assert turns[0]["role"] == "user"
        assert turns[0]["content"] == "Hello"
        assert turns[1]["role"] == "assistant"
        assert turns[2]["role"] == "user"
        assert turns[2]["content"] == "What is SSH?"
    
    def test_memory_with_knowledge_snippets(self, temp_db):
        """Test memory retrieval with knowledge snippets."""
        server_id = "test-server-01"
        thread_id = "thread-xyz"
        
        # Add some knowledge
        doc_id = temp_db.create_knowledge_doc(server_id, "SSH Guide")
        temp_db.add_knowledge_chunks(doc_id, [
            "SSH is a secure protocol for remote login",
            "Use ssh-keygen to generate SSH keys"
        ])
        
        # Add memory
        temp_db.append_memory(server_id, thread_id, "user", "Help with SSH")
        
        # Retrieve with query
        result = temp_db.retrieve_memory(server_id, thread_id, q="SSH keys", limit=5)
        
        assert len(result["turns"]) == 1
        assert len(result["snippets"]) > 0
        
        # Should find SSH-related snippet
        found_ssh = any("SSH" in snippet["text"] for snippet in result["snippets"])
        assert found_ssh
    
    def test_memory_summarization(self, temp_db):
        """Test memory summarization and cleanup."""
        server_id = "test-server-01"
        thread_id = "thread-summary"
        
        # Add multiple turns
        for i in range(15):
            role = "user" if i % 2 == 0 else "assistant"
            temp_db.append_memory(server_id, thread_id, role, f"Message {i}")
        
        # Create summary
        summary_id = temp_db.summarize_memory(
            server_id, 
            thread_id, 
            "User asked about network scanning, provided nmap examples"
        )
        
        assert summary_id > 0
        
        # Should have cleaned up old turns (keeping last 10)
        result = temp_db.retrieve_memory(server_id, thread_id, limit=20)
        assert len(result["turns"]) <= 10

class TestServerStatus:
    """Test server status management."""
    
    def test_server_status_update_and_retrieval(self, temp_db):
        """Test updating and retrieving server status."""
        server_id = "test-server-01"
        
        status_data = {
            "uptime": "2 days, 4:30",
            "disk_usage": "75.5% (100 GB free)",
            "services": [
                {"name": "ssh", "state": "active"},
                {"name": "nginx", "state": "inactive"}
            ],
            "alerts": [
                {"type": "warning", "message": "High CPU usage"}
            ],
            "last_scan": "2025-10-05T10:30:00Z"
        }
        
        # Update status
        temp_db.update_server_status(server_id, status_data)
        
        # Retrieve status
        result = temp_db.get_server_status(server_id)
        
        assert result["server_id"] == server_id
        assert result["uptime"] == status_data["uptime"]
        assert result["disk_usage"] == status_data["disk_usage"]
        assert result["services"] == status_data["services"]
        assert result["alerts"] == status_data["alerts"]
        assert result["last_scan"] == status_data["last_scan"]
        assert "updated_at" in result
    
    def test_nonexistent_server_status(self, temp_db):
        """Test retrieving status for non-existent server."""
        result = temp_db.get_server_status("nonexistent-server")
        assert result is None

if __name__ == "__main__":
    pytest.main([__file__, "-v"])