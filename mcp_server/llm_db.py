"""
LLM Configuration Database
Manages LLM config, knowledge base, and conversation memory
"""

import sqlite3
import json
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class LLMDatabase:
    """Database manager for LLM configuration and knowledge."""
    
    def __init__(self, db_path: str = "/var/lib/mcp/llm.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """Initialize database tables."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                -- LLM Configuration
                CREATE TABLE IF NOT EXISTS llm_config (
                    server_id TEXT PRIMARY KEY,
                    version TEXT NOT NULL,
                    system_prompt TEXT NOT NULL,
                    guardrails TEXT NOT NULL, -- JSON
                    runtime_hints TEXT NOT NULL, -- JSON
                    tools_allowed TEXT NOT NULL, -- JSON array
                    etag TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Knowledge Documents
                CREATE TABLE IF NOT EXISTS knowledge_docs (
                    doc_id TEXT PRIMARY KEY,
                    server_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    source TEXT,
                    tags TEXT, -- JSON array
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES llm_config(server_id)
                );
                
                -- Knowledge Chunks
                CREATE TABLE IF NOT EXISTS knowledge_chunks (
                    chunk_id TEXT PRIMARY KEY,
                    doc_id TEXT NOT NULL,
                    text TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (doc_id) REFERENCES knowledge_docs(doc_id) ON DELETE CASCADE
                );
                
                -- FTS5 index for knowledge search
                CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
                    chunk_id UNINDEXED,
                    doc_id UNINDEXED,
                    source UNINDEXED,
                    text,
                    content='knowledge_chunks',
                    content_rowid='rowid'
                );
                
                -- Triggers to maintain FTS index
                CREATE TRIGGER IF NOT EXISTS knowledge_ai AFTER INSERT ON knowledge_chunks BEGIN
                    INSERT INTO knowledge_fts(chunk_id, doc_id, source, text) 
                    SELECT NEW.chunk_id, NEW.doc_id, d.source, NEW.text 
                    FROM knowledge_docs d WHERE d.doc_id = NEW.doc_id;
                END;
                
                CREATE TRIGGER IF NOT EXISTS knowledge_ad AFTER DELETE ON knowledge_chunks BEGIN
                    DELETE FROM knowledge_fts WHERE chunk_id = OLD.chunk_id;
                END;
                
                -- Conversation Memory
                CREATE TABLE IF NOT EXISTS conversation_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id TEXT NOT NULL,
                    thread_id TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
                    content TEXT NOT NULL,
                    meta TEXT, -- JSON metadata
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES llm_config(server_id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_memory_thread ON conversation_memory(server_id, thread_id, created_at);
                
                -- Memory Summaries
                CREATE TABLE IF NOT EXISTS memory_summaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id TEXT NOT NULL,
                    thread_id TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    turn_count INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES llm_config(server_id)
                );
                
                -- Server Status (for live context)
                CREATE TABLE IF NOT EXISTS server_status (
                    server_id TEXT PRIMARY KEY,
                    uptime TEXT,
                    alerts TEXT, -- JSON array
                    services TEXT, -- JSON array
                    last_scan TEXT,
                    disk_usage TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES llm_config(server_id)
                );
            """)
    
    def _generate_etag(self, data: Dict[str, Any]) -> str:
        """Generate ETag for caching."""
        content = json.dumps(data, sort_keys=True)
        return hashlib.md5(content.encode()).hexdigest()[:8]
    
    # LLM Configuration Methods
    
    def get_llm_config(self, server_id: str) -> Optional[Dict[str, Any]]:
        """Get LLM configuration for server."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT version, system_prompt, guardrails, runtime_hints, 
                       tools_allowed, etag, updated_at
                FROM llm_config WHERE server_id = ?
            """, (server_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return {
                "version": row["version"],
                "server_id": server_id,
                "system_prompt": row["system_prompt"],
                "guardrails": json.loads(row["guardrails"]),
                "runtime_hints": json.loads(row["runtime_hints"]),
                "tools_allowed": json.loads(row["tools_allowed"]),
                "etag": row["etag"]
            }
    
    def set_llm_config(self, server_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Set LLM configuration for server."""
        version = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        etag = self._generate_etag(config)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO llm_config 
                (server_id, version, system_prompt, guardrails, runtime_hints, tools_allowed, etag)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                server_id,
                version,
                config.get("system_prompt", ""),
                json.dumps(config.get("guardrails", {})),
                json.dumps(config.get("runtime_hints", {})),
                json.dumps(config.get("tools_allowed", [])),
                etag
            ))
        
        return self.get_llm_config(server_id)
    
    def get_config_etag(self, server_id: str) -> Optional[str]:
        """Get ETag for config caching."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT etag FROM llm_config WHERE server_id = ?", (server_id,))
            row = cursor.fetchone()
            return row[0] if row else None
    
    # Knowledge Management Methods
    
    def create_knowledge_doc(self, server_id: str, title: str, source: str = None, 
                           tags: List[str] = None) -> str:
        """Create a knowledge document."""
        doc_id = str(uuid.uuid4())
        tags_json = json.dumps(tags or [])
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO knowledge_docs (doc_id, server_id, title, source, tags)
                VALUES (?, ?, ?, ?, ?)
            """, (doc_id, server_id, title, source, tags_json))
        
        return doc_id
    
    def update_knowledge_doc(self, doc_id: str, title: str = None, source: str = None,
                           tags: List[str] = None) -> bool:
        """Update knowledge document metadata."""
        updates = []
        params = []
        
        if title is not None:
            updates.append("title = ?")
            params.append(title)
        if source is not None:
            updates.append("source = ?")
            params.append(source)
        if tags is not None:
            updates.append("tags = ?")
            params.append(json.dumps(tags))
        
        if not updates:
            return False
        
        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(doc_id)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(f"""
                UPDATE knowledge_docs SET {', '.join(updates)} WHERE doc_id = ?
            """, params)
            return cursor.rowcount > 0
    
    def delete_knowledge_doc(self, doc_id: str) -> bool:
        """Delete knowledge document and its chunks."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM knowledge_docs WHERE doc_id = ?", (doc_id,))
            return cursor.rowcount > 0
    
    def add_knowledge_chunks(self, doc_id: str, chunks: List[str]) -> List[str]:
        """Add text chunks to a knowledge document."""
        chunk_ids = []
        
        with sqlite3.connect(self.db_path) as conn:
            for i, text in enumerate(chunks):
                chunk_id = str(uuid.uuid4())
                conn.execute("""
                    INSERT INTO knowledge_chunks (chunk_id, doc_id, text, chunk_index)
                    VALUES (?, ?, ?, ?)
                """, (chunk_id, doc_id, text, i))
                chunk_ids.append(chunk_id)
        
        return chunk_ids
    
    def search_knowledge(self, server_id: str, query: str, top_k: int = 4) -> Dict[str, Any]:
        """Search knowledge base using FTS5."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT f.chunk_id, f.doc_id, f.source, f.text, f.rank
                FROM knowledge_fts f
                JOIN knowledge_docs d ON f.doc_id = d.doc_id
                WHERE knowledge_fts MATCH ? AND d.server_id = ?
                ORDER BY rank
                LIMIT ?
            """, (query, server_id, top_k))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    "chunk_id": row["chunk_id"],
                    "doc_id": row["doc_id"],
                    "score": abs(row["rank"]),  # FTS5 rank is negative
                    "source": row["source"] or "unknown",
                    "text": row["text"]
                })
        
        return {
            "query": query,
            "results": results
        }
    
    def reindex_knowledge(self, server_id: str = None) -> int:
        """Rebuild knowledge search index."""
        with sqlite3.connect(self.db_path) as conn:
            if server_id:
                # Reindex specific server's documents
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM knowledge_chunks c
                    JOIN knowledge_docs d ON c.doc_id = d.doc_id
                    WHERE d.server_id = ?
                """, (server_id,))
            else:
                # Reindex all
                cursor = conn.execute("SELECT COUNT(*) FROM knowledge_chunks")
                conn.execute("DELETE FROM knowledge_fts")
                conn.execute("""
                    INSERT INTO knowledge_fts(chunk_id, doc_id, source, text)
                    SELECT c.chunk_id, c.doc_id, d.source, c.text
                    FROM knowledge_chunks c
                    JOIN knowledge_docs d ON c.doc_id = d.doc_id
                """)
            
            return cursor.fetchone()[0]
    
    # Memory Methods
    
    def append_memory(self, server_id: str, thread_id: str, role: str, 
                     content: str, meta: Dict[str, Any] = None) -> int:
        """Append a conversation turn to memory."""
        meta_json = json.dumps(meta or {})
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT INTO conversation_memory (server_id, thread_id, role, content, meta)
                VALUES (?, ?, ?, ?, ?)
            """, (server_id, thread_id, role, content, meta_json))
            return cursor.lastrowid
    
    def retrieve_memory(self, server_id: str, thread_id: str, query: str = None, 
                       limit: int = 8) -> Dict[str, Any]:
        """Retrieve conversation memory."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Get recent conversation turns
            cursor = conn.execute("""
                SELECT role, content, meta, created_at
                FROM conversation_memory
                WHERE server_id = ? AND thread_id = ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (server_id, thread_id, limit))
            
            turns = []
            for row in cursor.fetchall():
                turns.append({
                    "role": row["role"],
                    "content": row["content"],
                    "meta": json.loads(row["meta"]) if row["meta"] else {}
                })
            
            turns.reverse()  # Chronological order
            
            # Optional: Get relevant snippets if query provided
            snippets = []
            if query:
                knowledge_results = self.search_knowledge(server_id, query, top_k=3)
                snippets = [
                    {
                        "text": result["text"][:200] + "..." if len(result["text"]) > 200 else result["text"],
                        "meta": {"source": result["source"]}
                    }
                    for result in knowledge_results["results"]
                ]
        
        return {
            "thread_id": thread_id,
            "turns": turns,
            "snippets": snippets
        }
    
    def summarize_memory(self, server_id: str, thread_id: str, summary: str) -> int:
        """Add a memory summary and optionally clean old turns."""
        with sqlite3.connect(self.db_path) as conn:
            # Count turns
            cursor = conn.execute("""
                SELECT COUNT(*) FROM conversation_memory 
                WHERE server_id = ? AND thread_id = ?
            """, (server_id, thread_id))
            turn_count = cursor.fetchone()[0]
            
            # Add summary
            cursor = conn.execute("""
                INSERT INTO memory_summaries (server_id, thread_id, summary, turn_count)
                VALUES (?, ?, ?, ?)
            """, (server_id, thread_id, summary, turn_count))
            
            summary_id = cursor.lastrowid
            
            # Optional: Clean older turns (keep last 10)
            conn.execute("""
                DELETE FROM conversation_memory 
                WHERE server_id = ? AND thread_id = ? AND id NOT IN (
                    SELECT id FROM conversation_memory 
                    WHERE server_id = ? AND thread_id = ?
                    ORDER BY created_at DESC LIMIT 10
                )
            """, (server_id, thread_id, server_id, thread_id))
            
            return summary_id
    
    # Server Status Methods
    
    def update_server_status(self, server_id: str, status: Dict[str, Any]):
        """Update server status for live context."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO server_status 
                (server_id, uptime, alerts, services, last_scan, disk_usage)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                server_id,
                status.get("uptime"),
                json.dumps(status.get("alerts", [])),
                json.dumps(status.get("services", [])),
                status.get("last_scan"),
                status.get("disk_usage")
            ))
    
    def get_server_status(self, server_id: str) -> Optional[Dict[str, Any]]:
        """Get current server status."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT uptime, alerts, services, last_scan, disk_usage, updated_at
                FROM server_status WHERE server_id = ?
            """, (server_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return {
                "server_id": server_id,
                "uptime": row["uptime"],
                "alerts": json.loads(row["alerts"]) if row["alerts"] else [],
                "services": json.loads(row["services"]) if row["services"] else [],
                "last_scan": row["last_scan"],
                "disk_usage": row["disk_usage"],
                "updated_at": row["updated_at"]
            }

# Global database instance
llm_db = None

def get_llm_db() -> LLMDatabase:
    """Get or create the global LLM database instance."""
    global llm_db
    if llm_db is None:
        llm_db = LLMDatabase()
    return llm_db