"""
DICOM Router - HIPAA-compliant DICOM routing system
Copyright (C) 2024  MidCrusadero

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

================================================================================
orthanc-dicom-router.py - v3.5.0 Secure & Optimized
================================================================================

HIPAA-compliant DICOM Router with SQLite persistence
Changes in v3.5.0:
- PHI masking in logs (HIPAA compliance)
- Path traversal protection
- SQLite WAL mode for performance
- Circuit breaker pattern for network resilience
- Graceful shutdown handling
- Batch database inserts
- External HTML UI

"""

import orthanc
import json
import os
import re
import time
import logging
import threading
import platform
import sys
import atexit
import hashlib
import sqlite3
import signal
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set, Callable
from functools import wraps, lru_cache
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from queue import Queue, Empty
import traceback

# =============================================================================
# VERSION INFO
# =============================================================================

__version__ = "3.5.0"
__author__ = "MidCrusadero"


# =============================================================================
# SECURITY UTILITIES
# =============================================================================

class PHIFilter(logging.Filter):
    """
    HIPAA compliance filter - masks Protected Health Information in logs.
    Masks: PatientName, PatientID, AccessionNumber, StudyDescription (if contains name)
    """
    
    # Patterns to detect PHI in log messages
    PHI_PATTERNS = [
        (r'PatientName["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)', 'PatientName": "***"'),
        (r'PatientID["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)', 'PatientID": "***"'),
        (r'AccessionNumber["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)', 'AccessionNumber": "***"'),
        (r'PatientBirthDate["\']?\s*[:=]\s*["\']?(\d{8})', 'PatientBirthDate": "********"'),
    ]
    
    def filter(self, record):
        if not hasattr(record, 'msg'):
            return True
            
        msg = str(record.msg)
        original_msg = msg
        
        for pattern, replacement in self.PHI_PATTERNS:
            msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)
        
        # Also mask in args if it's a string
        new_args = []
        if record.args:
            for arg in record.args:
                if isinstance(arg, str):
                    masked_arg = arg
                    for pattern, replacement in self.PHI_PATTERNS:
                        masked_arg = re.sub(pattern, replacement, masked_arg, flags=re.IGNORECASE)
                    new_args.append(masked_arg)
                else:
                    new_args.append(arg)
            record.args = tuple(new_args)
        
        record.msg = msg
        return True


def validate_path(path: str, check_write: bool = True) -> Tuple[bool, str]:
    """
    Validate folder path with path traversal protection.
    Checks: existence, directory type, permissions, path traversal attacks.
    """
    try:
        # Normalize and get absolute path
        path = os.path.expandvars(os.path.expanduser(path))
        if not os.path.isabs(path):
            path = os.path.abspath(path)
        
        real_path = os.path.realpath(path)
        
        # Path Traversal Protection: ensure path is within allowed base
        # For watch folder, we allow any path but log warning if outside data dir
        data_dir_real = os.path.realpath(Config.DATA_DIR)
        if not real_path.startswith(data_dir_real) and not os.path.isabs(path):
            return False, f"Path traversal detected: {path} resolves outside allowed base"
        
        # Check existence
        if not os.path.exists(real_path):
            return False, f"Path does not exist: {path}"
        
        if not os.path.isdir(real_path):
            return False, f"Path is not a directory: {path}"
        
        # Check read permission
        if not os.access(real_path, os.R_OK):
            return False, f"No read permission for: {path}"
        
        # Check write permission if needed
        if check_write and not os.access(real_path, os.W_OK):
            return False, f"No write permission for: {path} (required for file operations)"
        
        # Actual write test
        if check_write:
            test_file = os.path.join(real_path, f'.test_{int(time.time())}.tmp')
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
            except PermissionError:
                return False, f"Write test failed: Permission denied (check folder security settings)"
            except Exception as e:
                return False, f"Write test failed: {str(e)}"
        
        return True, "Valid"
        
    except Exception as e:
        return False, f"Validation error: {str(e)}"


def security_check():
    """Pre-flight security checks."""
    if platform.system() != 'Windows':
        # Check if running as root (Linux/Unix)
        try:
            if os.getuid() == 0:
                logger.critical("SECURITY: Do not run as root! Use dedicated service account.")
                # Not exiting to allow testing, but logging critical warning
        except AttributeError:
            pass  # Windows doesn't have getuid
    
    # Check database file permissions
    if os.path.exists(Config.DB_PATH):
        try:
            import stat
            mode = os.stat(Config.DB_PATH).st_mode
            if mode & stat.S_IRWXO:  # Others have any access
                logger.warning(f"SECURITY: Database file permissions too open ({oct(mode)}). Consider chmod 600.")
        except Exception as e:
            logger.debug(f"Cannot check DB permissions: {e}")


# =============================================================================
# UTILITIES
# =============================================================================

def get_plugin_directory() -> str:
    """Get the directory where this plugin script is located."""
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except:
        return os.getcwd()


def ensure_directory(filepath: str) -> bool:
    """Ensure directory exists."""
    try:
        directory = os.path.dirname(filepath)
        if directory:
            os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        print(f"Failed to create directory: {e}")
        return False


def safe_json_loads(data: Any, default: Any = None) -> Any:
    """Safely parse JSON with fallback."""
    if data is None:
        return default
    try:
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return default


# =============================================================================
# CIRCUIT BREAKER PATTERN
# =============================================================================

class CircuitBreaker:
    """
    Prevents cascading failures by stopping calls to failing destinations.
    States: CLOSED (ok), OPEN (failing), HALF-OPEN (testing)
    """
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failures: Dict[str, int] = defaultdict(int)
        self.last_failure_time: Dict[str, float] = {}
        self.states: Dict[str, str] = defaultdict(lambda: 'CLOSED')  # CLOSED, OPEN, HALF_OPEN
        self._lock = threading.Lock()
    
    def can_call(self, destination: str) -> bool:
        """Check if call to destination is allowed."""
        with self._lock:
            state = self.states[destination]
            
            if state == 'CLOSED':
                return True
            
            if state == 'OPEN':
                last_fail = self.last_failure_time.get(destination, 0)
                if time.time() - last_fail > self.recovery_timeout:
                    self.states[destination] = 'HALF_OPEN'
                    logger.info(f"Circuit breaker for {destination}: HALF_OPEN (testing)")
                    return True
                return False
            
            if state == 'HALF_OPEN':
                return True
            
            return True
    
    def record_success(self, destination: str):
        """Record successful call."""
        with self._lock:
            if self.states[destination] == 'HALF_OPEN':
                self.states[destination] = 'CLOSED'
                self.failures[destination] = 0
                logger.info(f"Circuit breaker for {destination}: CLOSED (recovered)")
            else:
                self.failures[destination] = 0
    
    def record_failure(self, destination: str):
        """Record failed call."""
        with self._lock:
            self.failures[destination] += 1
            self.last_failure_time[destination] = time.time()
            
            if self.failures[destination] >= self.failure_threshold:
                if self.states[destination] != 'OPEN':
                    self.states[destination] = 'OPEN'
                    logger.error(f"Circuit breaker for {destination}: OPEN (too many failures)")
    
    def get_status(self, destination: str = None) -> Dict:
        """Get current circuit breaker status."""
        with self._lock:
            if destination:
                return {
                    'destination': destination,
                    'state': self.states[destination],
                    'failures': self.failures[destination]
                }
            return {
                dest: {'state': state, 'failures': self.failures[dest]}
                for dest, state in self.states.items()
            }


# Global circuit breaker instance
circuit_breaker = CircuitBreaker()


# =============================================================================
# DATABASE MANAGER (WITH WAL MODE & BATCHING)
# =============================================================================

class DatabaseManager:
    """SQLite database with WAL mode, batch inserts, and security features."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._batch_buffer = []
        self._batch_lock = threading.Lock()
        self._batch_size = 50
        self._last_flush = time.time()
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema with WAL mode."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                # Enable WAL mode for better concurrency and performance
                conn.execute('PRAGMA journal_mode=WAL')
                conn.execute('PRAGMA synchronous=NORMAL')
                conn.execute('PRAGMA temp_store=MEMORY')
                conn.execute('PRAGMA mmap_size=30000000000')  # 30GB mmap if possible
                
                cursor = conn.cursor()
                
                # Settings table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Processed files table with optimized indexes
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS processed_files (
                        file_hash TEXT PRIMARY KEY,
                        filepath TEXT,
                        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        file_size INTEGER,
                        patient_name TEXT
                    )
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_processed_time 
                    ON processed_files(processed_at)
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_hash 
                    ON processed_files(file_hash)
                ''')
                
                conn.commit()
                logger.info(f"Database initialized with WAL mode: {self.db_path}")
            finally:
                conn.close()
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get setting value from DB."""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.cursor()
                    cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
                    row = cursor.fetchone()
                    if row and row[0] is not None:
                        try:
                            return json.loads(row[0])
                        except:
                            return row[0]
                    return default
                finally:
                    conn.close()
        except Exception as e:
            logger.error(f"DB get_setting error: {e}")
            return default
    
    def set_setting(self, key: str, value: Any):
        """Save setting to DB."""
        try:
            if isinstance(value, (dict, list, bool, int, float)):
                value = json.dumps(value)
            else:
                value = str(value)
            
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO settings (key, value, updated_at) 
                        VALUES (?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(key) DO UPDATE SET 
                        value=excluded.value, 
                        updated_at=excluded.updated_at
                    ''', (key, value))
                    conn.commit()
                finally:
                    conn.close()
        except Exception as e:
            logger.error(f"DB set_setting error: {e}")
    
    def get_all_settings(self) -> Dict[str, Any]:
        """Get all settings from DB."""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.cursor()
                    cursor.execute('SELECT key, value FROM settings')
                    rows = cursor.fetchall()
                    result = {}
                    for key, value in rows:
                        try:
                            result[key] = json.loads(value)
                        except:
                            result[key] = value
                    return result
                finally:
                    conn.close()
        except Exception as e:
            logger.error(f"DB get_all_settings error: {e}")
            return {}
    
    def is_file_processed(self, file_hash: str) -> bool:
        """Check if file was already processed."""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.cursor()
                    cursor.execute('SELECT 1 FROM processed_files WHERE file_hash = ?', (file_hash,))
                    return cursor.fetchone() is not None
                finally:
                    conn.close()
        except Exception as e:
            logger.error(f"DB is_file_processed error: {e}")
            return False
    
    def add_processed_file(self, file_hash: str, filepath: str, file_size: int = 0, patient_name: str = ""):
        """Mark file as processed (buffered for batch insert)."""
        with self._batch_lock:
            self._batch_buffer.append((file_hash, filepath, file_size, patient_name))
            
            # Flush if buffer full or time exceeded
            if (len(self._batch_buffer) >= self._batch_size or 
                time.time() - self._last_flush > 5):
                self._flush_batch()
    
    def _flush_batch(self):
        """Execute batch insert of processed files."""
        if not self._batch_buffer:
            return
        
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.executemany('''
                    INSERT OR REPLACE INTO processed_files 
                    (file_hash, filepath, processed_at, file_size, patient_name)
                    VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?)
                ''', self._batch_buffer)
                conn.commit()
                count = len(self._batch_buffer)
                self._batch_buffer.clear()
                self._last_flush = time.time()
                if count > 0:
                    logger.debug(f"DB batch flush: {count} records")
            except Exception as e:
                logger.error(f"DB batch flush error: {e}")
            finally:
                conn.close()
    
    def get_processed_count(self) -> int:
        """Get total count of processed files."""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.cursor()
                    cursor.execute('SELECT COUNT(*) FROM processed_files')
                    row = cursor.fetchone()
                    return row[0] if row else 0
                finally:
                    conn.close()
        except Exception as e:
            logger.error(f"DB get_processed_count error: {e}")
            return 0
    
    def get_processed_hashes(self, limit: int = 50000) -> Set[str]:
        """Get set of processed file hashes."""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT file_hash FROM processed_files 
                        ORDER BY processed_at DESC 
                        LIMIT ?
                    ''', (limit,))
                    rows = cursor.fetchall()
                    return set(row[0] for row in rows)
                finally:
                    conn.close()
        except Exception as e:
            logger.error(f"DB get_processed_hashes error: {e}")
            return set()
    
    def cleanup_old_files(self, days: int = 30):
        """Remove entries older than N days."""
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.cursor()
                    cursor.execute('''
                        DELETE FROM processed_files 
                        WHERE processed_at < datetime('now', ?)
                    ''', (f'-{days} days',))
                    deleted = cursor.rowcount
                    conn.commit()
                    if deleted > 0:
                        logger.info(f"DB cleanup: removed {deleted} old entries")
                finally:
                    conn.close()
        except Exception as e:
            logger.error(f"DB cleanup_old_files error: {e}")
    
    def migrate_from_json(self, json_path: str):
        """Migrate data from old JSON format."""
        if not os.path.exists(json_path):
            return
        
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            processed = data.get('processed', [])
            
            if processed:
                logger.info(f"Migrating {len(processed)} entries from JSON to DB...")
                with self._lock:
                    conn = sqlite3.connect(self.db_path)
                    try:
                        cursor = conn.cursor()
                        # Batch insert for migration
                        batch = []
                        for file_hash in processed:
                            batch.append((file_hash, 'migrated_from_json', 0, ''))
                            if len(batch) >= 1000:
                                cursor.executemany('''
                                    INSERT OR IGNORE INTO processed_files 
                                    (file_hash, filepath, file_size, patient_name, processed_at)
                                    VALUES (?, ?, ?, ?, datetime('now', '-' || abs(random()) % 86400 || ' seconds'))
                                ''', batch)
                                batch = []
                        if batch:
                            cursor.executemany('''
                                INSERT OR IGNORE INTO processed_files 
                                (file_hash, filepath, file_size, patient_name, processed_at)
                                VALUES (?, ?, ?, ?, datetime('now', '-' || abs(random()) % 86400 || ' seconds'))
                            ''', batch)
                        conn.commit()
                    finally:
                        conn.close()
                
                backup_path = json_path + '.backup'
                os.rename(json_path, backup_path)
                logger.info(f"Migration complete. Backup: {backup_path}")
        except Exception as e:
            logger.error(f"Migration error: {e}")
    
    def close(self):
        """Close database, flush remaining batch."""
        self._flush_batch()
        logger.info("Database connection closed")


# Global database instance
db_manager: Optional[DatabaseManager] = None


# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    """Thread-safe configuration manager with DB persistence."""
    
    _lock = threading.Lock()
    
    PLUGIN_DIR: str = get_plugin_directory()
    DATA_DIR: str = os.getenv('ORTHANC_ROUTER_DATA', PLUGIN_DIR)
    RULES_FILE_PATH: str = os.path.join(DATA_DIR, 'routing-rules.json')
    LOG_FILE_PATH: str = os.path.join(DATA_DIR, 'router.log')
    DB_PATH: str = os.path.join(DATA_DIR, 'dicom-router.db')
    
    ORTHANC_URL: str = os.getenv('ORTHANC_URL', 'http://localhost:8042')
    ORTHANC_USERNAME: str = os.getenv('ORTHANC_USERNAME', '')
    ORTHANC_PASSWORD: str = os.getenv('ORTHANC_PASSWORD', '')
    
    MOVE_ORIGINATOR_AET: str = os.getenv('ORTHANC_MOVE_AET', 'ORTHANC')
    MOVE_ORIGINATOR_ID: int = int(os.getenv('ORTHANC_MOVE_ID', '0'))
    REQUESTED_TAGS: str = os.getenv('ORTHANC_REQUESTED_TAGS', '00080061')
    
    CONNECTIVITY_CHECK_ENABLED: bool = os.getenv('ORTHANC_CONNECTIVITY_CHECK', 'true').lower() == 'true'
    ECHO_TIMEOUT: int = int(os.getenv('ORTHANC_ECHO_TIMEOUT', '5'))
    ECHO_CACHE_TTL: int = int(os.getenv('ORTHANC_ECHO_CACHE_TTL', '60'))
    
    RETRY_INITIAL_DELAY: int = int(os.getenv('ORTHANC_RETRY_DELAY', '30'))
    RETRY_MAX_DELAY: int = int(os.getenv('ORTHANC_RETRY_MAX_DELAY', '600'))
    RETRY_BACKOFF_MULTIPLIER: float = float(os.getenv('ORTHANC_RETRY_BACKOFF', '2.0'))
    RETRY_MAX_ATTEMPTS: int = int(os.getenv('ORTHANC_RETRY_MAX_ATTEMPTS', '10'))
    RETRY_CHECK_INTERVAL: int = int(os.getenv('ORTHANC_RETRY_INTERVAL', '10'))
    
    ASYNC_FORWARD: bool = os.getenv('ORTHANC_ASYNC_FORWARD', 'true').lower() == 'true'
    COMPRESS: bool = os.getenv('ORTHANC_COMPRESS', 'true').lower() == 'true'
    STORAGE_COMMITMENT: bool = os.getenv('ORTHANC_STORAGE_COMMITMENT', 'false').lower() == 'false'
    
    MAX_RULES: int = int(os.getenv('ORTHANC_MAX_RULES', '100'))
    MAX_DEFERRED_TASKS: int = int(os.getenv('ORTHANC_MAX_DEFERRED', '1000'))
    MAX_LOG_ENTRIES: int = int(os.getenv('ORTHANC_MAX_LOG_ENTRIES', '1000'))
    MAX_HISTORY_ENTRIES: int = int(os.getenv('ORTHANC_MAX_HISTORY', '100'))
    
    PROCESSING_WORKERS: int = int(os.getenv('ORTHANC_PROCESSING_WORKERS', '2'))
    PROCESSING_QUEUE_SIZE: int = int(os.getenv('ORTHANC_QUEUE_SIZE', '100'))
    
    API_RATE_LIMIT: int = int(os.getenv('ORTHANC_API_RATE_LIMIT', '60'))
    
    LOG_LEVEL: str = os.getenv('ORTHANC_LOG_LEVEL', 'INFO')
    
    ROUTER_ENABLED: bool = True
    
    # Stable mode: 'study' - wait for complete study, 'series' - route per series
    STABLE_MODE: str = os.getenv('ORTHANC_STABLE_MODE', 'study').lower()
    
    WATCH_FOLDER_ENABLED: bool = os.getenv('ORTHANC_WATCH_ENABLED', 'false').lower() == 'true'
    WATCH_FOLDER_PATH: str = os.getenv('ORTHANC_WATCH_PATH', r'C:\Orthanc\Incoming' if platform.system() == 'Windows' else '/var/lib/orthanc/incoming')
    WATCH_FOLDER_INTERVAL: int = int(os.getenv('ORTHANC_WATCH_INTERVAL', '5'))
    WATCH_FOLDER_EXTENSIONS: str = os.getenv('ORTHANC_WATCH_EXTENSIONS', '.dcm,.bin')
    WATCH_FOLDER_CLEANUP_ENABLED: bool = os.getenv('ORTHANC_WATCH_CLEANUP', 'false').lower() == 'true'
    WATCH_FOLDER_CLEANUP_INTERVAL: int = int(os.getenv('ORTHANC_WATCH_CLEANUP_INTERVAL', '600'))
    WATCH_FOLDER_DELETE_ORIGINALS: bool = os.getenv('ORTHANC_WATCH_DELETE_ORIGINALS', 'true').lower() == 'true'
    WATCH_FOLDER_DB_PATH: str = os.path.join(DATA_DIR, 'watchfolder-db.json')
    
    WATCH_FOLDER_BATCH_INTERVAL: int = int(os.getenv('ORTHANC_WATCH_BATCH_INTERVAL', '30'))
    WATCH_FOLDER_MIN_FILE_AGE: int = int(os.getenv('ORTHANC_WATCH_MIN_FILE_AGE', '60'))
    WATCH_FOLDER_MAX_DEPTH: int = int(os.getenv('ORTHANC_WATCH_MAX_DEPTH', '5'))
    WATCH_FOLDER_STAGING_PATH: str = os.getenv('ORTHANC_WATCH_STAGING', os.path.join(DATA_DIR, 'watch_staging'))
    
    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        with cls._lock:
            return {
                'DATA_DIR': cls.DATA_DIR,
                'RULES_FILE_PATH': cls.RULES_FILE_PATH,
                'CONNECTIVITY_CHECK_ENABLED': cls.CONNECTIVITY_CHECK_ENABLED,
                'ECHO_TIMEOUT': cls.ECHO_TIMEOUT,
                'ECHO_CACHE_TTL': cls.ECHO_CACHE_TTL,
                'RETRY_INITIAL_DELAY': cls.RETRY_INITIAL_DELAY,
                'RETRY_MAX_DELAY': cls.RETRY_MAX_DELAY,
                'RETRY_MAX_ATTEMPTS': cls.RETRY_MAX_ATTEMPTS,
                'RETRY_CHECK_INTERVAL': cls.RETRY_CHECK_INTERVAL,
                'ASYNC_FORWARD': cls.ASYNC_FORWARD,
                'COMPRESS': cls.COMPRESS,
                'PROCESSING_WORKERS': cls.PROCESSING_WORKERS,
                'ROUTER_ENABLED': cls.ROUTER_ENABLED,
                'STABLE_MODE': cls.STABLE_MODE,
                'LOG_LEVEL': cls.LOG_LEVEL,
                'WATCH_FOLDER_ENABLED': cls.WATCH_FOLDER_ENABLED,
                'WATCH_FOLDER_PATH': cls.WATCH_FOLDER_PATH,
                'WATCH_FOLDER_INTERVAL': cls.WATCH_FOLDER_INTERVAL,
                'WATCH_FOLDER_EXTENSIONS': cls.WATCH_FOLDER_EXTENSIONS,
                'WATCH_FOLDER_CLEANUP_ENABLED': cls.WATCH_FOLDER_CLEANUP_ENABLED,
                'WATCH_FOLDER_CLEANUP_INTERVAL': cls.WATCH_FOLDER_CLEANUP_INTERVAL,
                'WATCH_FOLDER_DELETE_ORIGINALS': cls.WATCH_FOLDER_DELETE_ORIGINALS,
                'WATCH_FOLDER_BATCH_INTERVAL': cls.WATCH_FOLDER_BATCH_INTERVAL,
                'WATCH_FOLDER_MIN_FILE_AGE': cls.WATCH_FOLDER_MIN_FILE_AGE,
                'WATCH_FOLDER_MAX_DEPTH': cls.WATCH_FOLDER_MAX_DEPTH,
            }
    
    @classmethod
    def load_from_db(cls):
        """Load settings from SQLite database."""
        global db_manager
        if not db_manager:
            return
        
        try:
            settings = db_manager.get_all_settings()
            with cls._lock:
                for key, value in settings.items():
                    if hasattr(cls, key):
                        current = getattr(cls, key)
                        if isinstance(current, bool):
                            value = bool(value)
                        elif isinstance(current, int):
                            try:
                                value = int(value)
                            except:
                                continue
                        elif isinstance(current, float):
                            try:
                                value = float(value)
                            except:
                                continue
                        setattr(cls, key, value)
                        logger.debug(f"Loaded from DB: {key} = {value}")
            
            if settings:
                logger.info(f"Loaded {len(settings)} settings from database")
        except Exception as e:
            logger.error(f"Error loading settings from DB: {e}")
    
    @classmethod
    def update(cls, updates: Dict[str, Any]) -> List[str]:
        """Update config and return list of changed keys."""
        global watch_folder_manager, db_manager
        
        changed = []
        with cls._lock:
            for key, value in updates.items():
                if hasattr(cls, key):
                    old_value = getattr(cls, key)
                    
                    if key == 'WATCH_FOLDER_PATH' and isinstance(value, str):
                        value = value.replace('\\\\?\\', '').replace('\\\\?\\UNC\\', '\\\\')
                    
                    if isinstance(old_value, bool):
                        value = str(value).lower() in ('true', '1', 'yes', 'on')
                    elif isinstance(old_value, int):
                        value = int(value)
                    elif isinstance(old_value, float):
                        value = float(value)
                    elif key == 'LOG_LEVEL':
                        value = str(value).upper()
                        if value not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                            value = 'INFO'
                    elif key == 'STABLE_MODE':
                        value = str(value).lower()
                        if value not in ['study', 'series']:
                            value = 'study'
                    elif key == 'WATCH_FOLDER_EXTENSIONS':
                        value = str(value)
                    
                    if old_value != value:
                        setattr(cls, key, value)
                        changed.append(key)
                        
                        if db_manager:
                            db_manager.set_setting(key, value)
                        
                        if key == 'LOG_LEVEL':
                            logger.setLevel(getattr(logging, value, logging.INFO))
                            logger.info(f"Log level changed to {value}")
                        
                        if key.startswith('WATCH_FOLDER_') and watch_folder_manager:
                            if key == 'WATCH_FOLDER_ENABLED':
                                if value and not watch_folder_manager.is_alive():
                                    watch_folder_manager.start()
                                elif not value and watch_folder_manager.is_alive():
                                    watch_folder_manager.stop()
                            
                            elif key == 'WATCH_FOLDER_PATH':
                                logger.info(f"Watch Folder: path changed to {value}")
                                if watch_folder_manager.is_alive():
                                    watch_folder_manager.stop()
                                watch_folder_manager = WatchFolderManager()
                                if Config.WATCH_FOLDER_ENABLED:
                                    watch_folder_manager.start()
                                    logger.info(f"Watch Folder: restarted with new path")
        return changed


# Ensure directories exist
ensure_directory(Config.RULES_FILE_PATH)
ensure_directory(Config.LOG_FILE_PATH)


# =============================================================================
# LOGGING (WITH PHI FILTER)
# =============================================================================

class CircularLogBuffer:
    """Thread-safe circular buffer for logs."""
    
    __slots__ = ['_buffer', '_lock', '_max_size']
    
    def __init__(self, max_size: int = 1000):
        self._buffer = deque(maxlen=max_size)
        self._lock = threading.Lock()
        self._max_size = max_size
    
    def append(self, entry: Dict[str, Any]):
        with self._lock:
            self._buffer.append(entry)
    
    def get_recent(self, limit: int = 100, level: str = None) -> List[Dict]:
        with self._lock:
            logs = list(self._buffer)
        
        if level and level != 'ALL':
            logs = [l for l in logs if l.get('level') == level]
        
        return logs[-limit:]
    
    def clear(self):
        with self._lock:
            self._buffer.clear()


log_buffer = CircularLogBuffer(Config.MAX_LOG_ENTRIES)


class BufferHandler(logging.Handler):
    """Handler that writes to circular buffer."""
    
    def emit(self, record):
        try:
            log_buffer.append({
                'timestamp': datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S'),
                'level': record.levelname,
                'name': record.name,
                'message': record.getMessage()
            })
        except Exception:
            pass


def setup_logging():
    """Configure logging with PHI filter."""
    logger = logging.getLogger('dicom-router')
    logger.setLevel(getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Add PHI Filter
    phi_filter = PHIFilter()
    logger.addFilter(phi_filter)
    
    # File handler
    try:
        file_handler = logging.FileHandler(Config.LOG_FILE_PATH, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s | %(levelname)s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        file_handler.addFilter(phi_filter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Could not create file handler: {e}")
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%H:%M:%S'
    ))
    console_handler.addFilter(phi_filter)
    logger.addHandler(console_handler)
    
    # Buffer handler
    buffer_handler = BufferHandler()
    buffer_handler.addFilter(phi_filter)
    logger.addHandler(buffer_handler)
    
    return logger


logger = setup_logging()


# =============================================================================
# METRICS & STATISTICS
# =============================================================================

class Metrics:
    """Thread-safe metrics collection."""
    
    __slots__ = ['_counters', '_timings', '_lock', '_history', '_watch_folder_logs']
    
    def __init__(self):
        self._counters: Dict[str, int] = defaultdict(int)
        self._timings: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._history: deque = deque(maxlen=Config.MAX_HISTORY_ENTRIES)
        self._watch_folder_logs: deque = deque(maxlen=50)
    
    def increment(self, name: str, value: int = 1):
        with self._lock:
            self._counters[name] += value
    
    def record_timing(self, name: str, duration_ms: float):
        with self._lock:
            if name not in self._timings:
                self._timings[name] = deque(maxlen=100)
            self._timings[name].append(duration_ms)
    
    def add_history(self, entry: Dict[str, Any]):
        with self._lock:
            entry['timestamp'] = datetime.utcnow().isoformat()
            self._history.append(entry)
    
    def add_watch_folder_log(self, event_type: str, filename: str, details: str = ""):
        with self._lock:
            self._watch_folder_logs.append({
                'timestamp': datetime.utcnow().isoformat(),
                'type': event_type,
                'filename': filename,
                'details': details
            })
    
    def get_watch_folder_logs(self, limit: int = 20) -> List[Dict]:
        with self._lock:
            return list(self._watch_folder_logs)[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            timing_stats = {}
            for name, values in self._timings.items():
                if values:
                    timing_stats[name] = {
                        'avg_ms': sum(values) / len(values),
                        'min_ms': min(values),
                        'max_ms': max(values),
                        'count': len(values)
                    }
            
            return {
                'counters': dict(self._counters),
                'timings': timing_stats,
                'history_size': len(self._history)
            }
    
    def get_history(self, limit: int = 50) -> List[Dict]:
        with self._lock:
            return list(self._history)[-limit:]


metrics = Metrics()


def timed(metric_name: str):
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                duration_ms = (time.perf_counter() - start) * 1000
                metrics.record_timing(metric_name, duration_ms)
        return wrapper
    return decorator


# =============================================================================
# WATCH FOLDER MODULE
# =============================================================================

class WatchFolderManager(threading.Thread):
    """Background thread with database-backed file tracking."""
    
    def __init__(self):
        super().__init__()
        self.daemon = True
        self._shutdown = threading.Event()
        self._processed_files: Set[str] = set()
        self._lock = threading.Lock()
        self._last_scan: Optional[datetime] = None
        self._files_processed = 0
        self._last_cleanup = time.time()
        self._running = False
        
        self._pending_files: Set[str] = set()
        self._batch_lock = threading.Lock()
        self._last_batch_time = time.time()
        self._staging_path = Config.WATCH_FOLDER_STAGING_PATH
        
        self._folder_path = self._normalize_path(Config.WATCH_FOLDER_PATH)
        
        self._load_from_db()
        self._ensure_staging()
        self._ensure_folder()
    
    def _normalize_path(self, path: str) -> str:
        try:
            path = os.path.expandvars(os.path.expanduser(path))
            if not os.path.isabs(path):
                path = os.path.abspath(path)
            return path
        except Exception as e:
            logger.error(f"Watch Folder: path normalization error: {e}")
            return path
    
    def _ensure_staging(self):
        try:
            os.makedirs(self._staging_path, exist_ok=True)
            logger.info(f"Watch Folder: staging area {self._staging_path}")
        except Exception as e:
            logger.error(f"Watch Folder: cannot create staging: {e}")
    
    def _ensure_folder(self):
        try:
            folder = self._folder_path
            
            if not os.path.exists(folder):
                logger.warning(f"Watch Folder: folder does not exist: {folder}")
                return
            
            if not os.path.isdir(folder):
                logger.error(f"Watch Folder: path is not a directory: {folder}")
                return
            
            is_valid, msg = validate_path(folder, Config.WATCH_FOLDER_DELETE_ORIGINALS)
            if is_valid:
                logger.info(f"Watch Folder: monitoring {folder}")
            else:
                logger.error(f"Watch Folder: validation failed - {msg}")
                
        except Exception as e:
            logger.error(f"Watch Folder: cannot check folder: {e}")
    
    def _load_from_db(self):
        global db_manager
        if db_manager:
            self._processed_files = db_manager.get_processed_hashes()
            self._files_processed = db_manager.get_processed_count()
            logger.info(f"Watch Folder: loaded {len(self._processed_files)} hashes from DB")
    
    def _save_to_db(self, file_hash: str, filepath: str, size: int = 0, patient: str = ""):
        global db_manager
        if db_manager:
            db_manager.add_processed_file(file_hash, filepath, size, patient)
    
    def _get_file_hash(self, filepath: str) -> str:
        try:
            stat = os.stat(filepath)
            return hashlib.md5(f"{filepath}:{stat.st_size}:{stat.st_mtime}".encode()).hexdigest()
        except:
            return hashlib.md5(filepath.encode()).hexdigest()
    
    def _get_extensions(self) -> List[str]:
        ext_str = Config.WATCH_FOLDER_EXTENSIONS
        exts = []
        for x in ext_str.split(','):
            x = x.strip()
            if x:
                if not x.startswith('.'):
                    x = '.' + x
                exts.append(x.lower())
                if platform.system() == 'Windows':
                    exts.append(x.upper())
        return exts
    
    def _is_file_ready(self, filepath: str) -> bool:
        filename = os.path.basename(filepath)
        
        try:
            if not os.path.exists(filepath):
                return False
            
            stat = os.stat(filepath)
            if stat.st_size == 0:
                return False
            
            file_age = time.time() - stat.st_mtime
            if file_age < Config.WATCH_FOLDER_MIN_FILE_AGE:
                return False
            
            if platform.system() == 'Windows':
                try:
                    fd = os.open(filepath, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
                    os.close(fd)
                except (OSError, IOError):
                    return False
            
            size1 = stat.st_size
            time.sleep(0.2)
            size2 = os.path.getsize(filepath)
            
            if size1 != size2:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Watch Folder: error checking file {filename}: {e}")
            return False
    
    def scan_folder(self):
        start_time = time.time()
        found_count = 0
        scanned_dirs = 0
        
        try:
            folder = self._folder_path
            
            if not os.path.exists(folder) or not os.path.isdir(folder):
                return
            
            for root, dirs, files in os.walk(folder):
                try:
                    depth = root.count(os.sep) - folder.count(os.sep)
                except:
                    depth = 0
                
                if depth > Config.WATCH_FOLDER_MAX_DEPTH:
                    dirs[:] = []
                    continue
                
                scanned_dirs += 1
                
                for filename in files:
                    if self._shutdown.is_set():
                        break
                    
                    if filename.startswith('~') or filename.startswith('.') or filename.endswith('.tmp'):
                        continue
                    
                    filepath = os.path.join(root, filename)
                    
                    extensions = self._get_extensions()
                    file_ext = Path(filename).suffix
                    if extensions and file_ext not in extensions:
                        continue
                    
                    file_hash = self._get_file_hash(filepath)
                    with self._lock:
                        if file_hash in self._processed_files:
                            continue
                    
                    global db_manager
                    if db_manager and db_manager.is_file_processed(file_hash):
                        with self._lock:
                            self._processed_files.add(file_hash)
                        continue
                    
                    with self._batch_lock:
                        if filepath in self._pending_files:
                            continue
                    
                    if self._is_file_ready(filepath):
                        with self._batch_lock:
                            self._pending_files.add(filepath)
                            found_count += 1
        
        except Exception as e:
            logger.error(f"Watch Folder: scan error: {e}")
        
        self._last_scan = datetime.utcnow()
        
        if found_count > 0:
            logger.info(f"Watch Folder: scan complete - {found_count} new files queued")
    
    def process_batch(self):
        with self._batch_lock:
            files_to_process = list(self._pending_files)
            self._pending_files.clear()
        
        if not files_to_process:
            return
        
        batch_size = len(files_to_process)
        logger.info(f"Watch Folder: processing batch of {batch_size} files")
        metrics.add_watch_folder_log('BATCH_START', f"Size: {batch_size}", "Processing")
        
        success_count = 0
        fail_count = 0
        
        for filepath in files_to_process:
            if self._shutdown.is_set():
                with self._batch_lock:
                    self._pending_files.update(files_to_process[files_to_process.index(filepath):])
                break
            
            try:
                if self._process_single_file(filepath):
                    success_count += 1
                else:
                    fail_count += 1
            except Exception as e:
                logger.error(f"Watch Folder: failed to process {filepath}: {e}")
                fail_count += 1
            
            time.sleep(0.01)
        
        metrics.add_watch_folder_log('BATCH_COMPLETE', f"Success: {success_count}, Failed: {fail_count}", "Complete")
        logger.info(f"Watch Folder: batch complete - OK:{success_count}, Failed:{fail_count}")
    
    def _process_single_file(self, filepath: str) -> bool:
        filename = os.path.basename(filepath)
        
        try:
            if not self._is_file_ready(filepath):
                return False
            
            file_size = os.path.getsize(filepath)
            metrics.add_watch_folder_log('PROCESSING', filename, f"Size: {file_size} bytes")
            
            with open(filepath, 'rb') as f:
                content = f.read()
            
            if not content:
                logger.warning(f"Watch Folder: empty file {filename}")
                return False
            
            logger.info(f"Watch Folder: uploading {filename} ({len(content)} bytes)...")
            response = orthanc.RestApiPost('/instances', content)
            result = safe_json_loads(response, {})
            
            if not result or 'ID' not in result:
                logger.error(f"Watch Folder: import failed for {filename}")
                metrics.increment('watchfolder_failed')
                return False
            
            instance_id = result['ID']
            patient_name = ""
            
            try:
                tags_resp = orthanc.RestApiGet(f'/instances/{instance_id}/simplified-tags')
                tags = safe_json_loads(tags_resp, {})
                patient_name = tags.get('PatientName', 'Unknown')
                study_desc = tags.get('StudyDescription', 'Unknown')
                log_msg = f"Imported: {patient_name} - {study_desc}"
                logger.info(f"Watch Folder: imported {filename}")
                metrics.add_watch_folder_log('IMPORTED', filename, "Study processed")
                
            except Exception as e:
                logger.debug(f"Watch Folder: metadata error: {e}")
                metrics.add_watch_folder_log('IMPORTED', filename, f"ID: {instance_id}")
            
            file_hash = self._get_file_hash(filepath)
            with self._lock:
                self._processed_files.add(file_hash)
                self._files_processed += 1
            
            self._save_to_db(file_hash, filepath, file_size, patient_name)
            
            if Config.WATCH_FOLDER_DELETE_ORIGINALS:
                try:
                    time.sleep(0.1)
                    os.remove(filepath)
                except Exception as e:
                    logger.error(f"Watch Folder: cannot delete {filename}: {e}")
            
            metrics.increment('watchfolder_imported')
            return True
            
        except Exception as e:
            logger.error(f"Watch Folder: error processing {filename}: {e}")
            metrics.increment('watchfolder_failed')
            return False
    
    def run(self):
        logger.info("Watch Folder: thread started")
        self._running = True
        
        while not self._shutdown.is_set():
            try:
                if Config.WATCH_FOLDER_ENABLED:
                    self.scan_folder()
                    
                    current_time = time.time()
                    batch_interval = Config.WATCH_FOLDER_BATCH_INTERVAL
                    
                    if (current_time - self._last_batch_time >= batch_interval and 
                        self._pending_files):
                        self.process_batch()
                        self._last_batch_time = current_time
                    
                    if Config.WATCH_FOLDER_CLEANUP_ENABLED:
                        if current_time - self._last_cleanup > Config.WATCH_FOLDER_CLEANUP_INTERVAL:
                            self._cleanup_old_files()
                            self._last_cleanup = current_time
            
                self._shutdown.wait(min(Config.WATCH_FOLDER_INTERVAL, 5))
                
            except Exception as e:
                logger.error(f"Watch Folder: thread error: {e}")
                time.sleep(5)
        
        if self._pending_files:
            self.process_batch()
        
        global db_manager
        if db_manager:
            db_manager.close()
        
        logger.info("Watch Folder: thread stopped")
    
    def _cleanup_old_files(self):
        """Cleanup old DB entries AND old files from filesystem."""
        global db_manager
        
        # Cleanup database
        if db_manager:
            db_manager.cleanup_old_files(days=30)
        
        # Cleanup filesystem - remove files older than cleanup_interval
        if not Config.WATCH_FOLDER_CLEANUP_ENABLED:
            return
            
        try:
            now = time.time()
            max_age = Config.WATCH_FOLDER_CLEANUP_INTERVAL  # используем это значение
            
            deleted_count = 0
            folder = self._folder_path
            
            if not os.path.exists(folder):
                return
                
            for root, dirs, files in os.walk(folder):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    try:
                        # Skip if in processed DB (recently handled)
                        file_hash = self._get_file_hash(filepath)
                        if file_hash in self._processed_files:
                            continue
                            
                        # Check file age
                        stat = os.stat(filepath)
                        file_age = now - stat.st_mtime
                        
                        if file_age > max_age:
                            os.remove(filepath)
                            deleted_count += 1
                            logger.info(f"Cleanup: deleted old file {filename} (age: {file_age/600:.1f}h)")
                            
                    except Exception as e:
                        logger.debug(f"Cleanup: cannot remove {filename}: {e}")
            
            if deleted_count > 0:
                logger.info(f"Cleanup complete: removed {deleted_count} old files")
                
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
    
    def start(self):
        if self.is_alive():
            return
        
        is_valid, msg = validate_path(self._folder_path, Config.WATCH_FOLDER_DELETE_ORIGINALS)
        if not is_valid:
            logger.error(f"Watch Folder: cannot start - {msg}")
            return
        
        logger.info(f"Watch Folder: starting")
        self._shutdown.clear()
        self._running = True
        super().start()
    
    def stop(self):
        logger.info("Watch Folder: stopping...")
        self._shutdown.set()
        self._running = False
        if self.is_alive():
            self.join(timeout=10)
        
        global db_manager
        if db_manager:
            db_manager.close()
    
    def get_status(self) -> Dict[str, Any]:
        files_count = 0
        try:
            if os.path.exists(self._folder_path):
                for root, dirs, files in os.walk(self._folder_path):
                    files_count += len(files)
        except:
            pass
        
        pending_count = 0
        with self._batch_lock:
            pending_count = len(self._pending_files)
        
        is_valid = False
        validation_msg = "Not checked"
        if os.path.exists(self._folder_path):
            is_valid, validation_msg = validate_path(self._folder_path, False)
        else:
            validation_msg = "Path does not exist"
            
        return {
            'enabled': Config.WATCH_FOLDER_ENABLED,
            'running': self.is_alive(),
            'folder': self._folder_path,
            'folder_valid': is_valid,
            'validation_message': validation_msg,
            'last_scan': self._last_scan.isoformat() if self._last_scan else None,
            'files_processed': self._files_processed,
            'files_pending': pending_count,
            'db_size': len(self._processed_files),
            'interval': Config.WATCH_FOLDER_INTERVAL,
            'batch_interval': Config.WATCH_FOLDER_BATCH_INTERVAL,
            'min_file_age': Config.WATCH_FOLDER_MIN_FILE_AGE,
            'max_depth': Config.WATCH_FOLDER_MAX_DEPTH,
            'extensions': list(set([e.lower() for e in self._get_extensions()])),
            'cleanup_enabled': Config.WATCH_FOLDER_CLEANUP_ENABLED,
            'delete_originals': Config.WATCH_FOLDER_DELETE_ORIGINALS,
            'current_files_in_folder': files_count,
            'thread_alive': self.is_alive(),
            'platform': platform.system()
        }
    
    def trigger_scan(self):
        if self._running:
            threading.Thread(target=self.scan_folder, daemon=True).start()


watch_folder_manager: Optional[WatchFolderManager] = None


# =============================================================================
# RATE LIMITER & QUEUES
# =============================================================================

class RateLimiter:
    def __init__(self, requests_per_minute: int):
        self._capacity = requests_per_minute
        self._tokens = float(requests_per_minute)
        self._last_update = time.monotonic()
        self._lock = threading.Lock()
    
    def acquire(self) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_update
            self._tokens = min(self._capacity, self._tokens + elapsed * (self._capacity / 60))
            self._last_update = now
            
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False


api_rate_limiter = RateLimiter(Config.API_RATE_LIMIT)


def rate_limited(output, func: Callable):
    if not api_rate_limiter.acquire():
        output.SendHttpStatus(429, json.dumps({
            'error': 'Rate limit exceeded',
            'retry_after': 60
        }))
        return None
    return func()


# =============================================================================
# DEFERRED TASK QUEUE
# =============================================================================

class TaskStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    DEFERRED = "deferred"


@dataclass
class ForwardTask:
    study_id: str
    destination: str
    patient_name: str = ""
    modality: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    next_retry_at: datetime = field(default_factory=datetime.utcnow)
    retry_count: int = 0
    last_error: Optional[str] = None
    status: TaskStatus = TaskStatus.PENDING
    
    def __post_init__(self):
        if isinstance(self.modality, list):
            self.modality = '\\'.join(self.modality)
        self.modality = str(self.modality or '')
        self.patient_name = str(self.patient_name or '')
    
    def calculate_next_retry(self) -> datetime:
        delay = min(
            Config.RETRY_INITIAL_DELAY * (Config.RETRY_BACKOFF_MULTIPLIER ** self.retry_count),
            Config.RETRY_MAX_DELAY
        )
        return datetime.utcnow() + timedelta(seconds=delay)
    
    def should_retry(self) -> bool:
        if Config.RETRY_MAX_ATTEMPTS == 0:
            return True
        return self.retry_count < Config.RETRY_MAX_ATTEMPTS
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'study_id': self.study_id,
            'destination': self.destination,
            'patient_name': self.patient_name,
            'modality': self.modality,
            'created_at': self.created_at.isoformat(),
            'next_retry_at': self.next_retry_at.isoformat(),
            'retry_count': self.retry_count,
            'last_error': self.last_error,
            'status': self.status.value
        }


class DeferredTaskQueue:
    def __init__(self):
        self._tasks: Dict[str, ForwardTask] = {}
        self._lock = threading.RLock()
        self._worker: Optional[threading.Thread] = None
        self._shutdown = threading.Event()
    
    def add(self, study_id: str, destination: str, error: str = "",
            patient_name: str = "", modality: str = "") -> bool:
        key = f"{study_id}:{destination}"
        
        with self._lock:
            if key in self._tasks:
                task = self._tasks[key]
                task.retry_count += 1
                task.last_error = error
                task.next_retry_at = task.calculate_next_retry()
                task.status = TaskStatus.DEFERRED
                
                if not task.should_retry():
                    del self._tasks[key]
                    metrics.increment('tasks_failed')
                    return False
                
                logger.info(f"Task deferred: {key}, retry #{task.retry_count}")
            else:
                if len(self._tasks) >= Config.MAX_DEFERRED_TASKS:
                    return False
                
                task = ForwardTask(
                    study_id=study_id,
                    destination=destination,
                    patient_name=patient_name,
                    modality=modality,
                    last_error=error,
                    status=TaskStatus.DEFERRED
                )
                task.next_retry_at = task.calculate_next_retry()
                self._tasks[key] = task
            
            metrics.increment('tasks_deferred')
            return True
    
    def get_ready(self) -> List[ForwardTask]:
        now = datetime.utcnow()
        ready = []
        with self._lock:
            for task in self._tasks.values():
                if task.status == TaskStatus.DEFERRED and task.next_retry_at <= now:
                    task.status = TaskStatus.IN_PROGRESS
                    ready.append(task)
        return ready
    
    def complete(self, study_id: str, destination: str, success: bool, error: str = "",
                 patient_name: str = "", modality: str = ""):
        key = f"{study_id}:{destination}"
        with self._lock:
            if key not in self._tasks:
                return
            task = self._tasks[key]
            if success:
                del self._tasks[key]
                metrics.increment('tasks_completed')
            else:
                self.add(study_id, destination, error, patient_name, modality)
    
    def get_all(self) -> List[Dict]:
        with self._lock:
            return [t.to_dict() for t in self._tasks.values()]
    
    def clear(self) -> int:
        with self._lock:
            count = len(self._tasks)
            self._tasks.clear()
            return count
    
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            by_status = defaultdict(int)
            for t in self._tasks.values():
                by_status[t.status.value] += 1
            return {
                'total_tasks': len(self._tasks),
                'by_status': dict(by_status),
                'max_capacity': Config.MAX_DEFERRED_TASKS
            }
    
    def start_worker(self):
        if self._worker and self._worker.is_alive():
            return
        self._shutdown.clear()
        self._worker = threading.Thread(
            target=self._worker_loop,
            name='deferred-worker',
            daemon=True
        )
        self._worker.start()
    
    def stop_worker(self):
        self._shutdown.set()
        if self._worker:
            self._worker.join(timeout=5)
    
    def _worker_loop(self):
        while not self._shutdown.is_set():
            try:
                if Config.ROUTER_ENABLED:
                    for task in self.get_ready():
                        if self._shutdown.is_set():
                            break
                        connectivity_checker.invalidate(task.destination)
                        is_ok, error = connectivity_checker.check(task.destination, use_cache=False)
                        if is_ok:
                            try:
                                forward_to_modality(task.destination, task.study_id)
                                self.complete(task.study_id, task.destination, True)
                            except Exception as e:
                                self.complete(task.study_id, task.destination, False, str(e),
                                            task.patient_name, task.modality)
                        else:
                            self.complete(task.study_id, task.destination, False, error,
                                        task.patient_name, task.modality)
            except Exception as e:
                logger.error(f"Worker error: {e}")
            self._shutdown.wait(Config.RETRY_CHECK_INTERVAL)


deferred_queue = DeferredTaskQueue()


# =============================================================================
# ASYNC STUDY PROCESSING QUEUE
# =============================================================================

class StudyProcessingQueue:
    def __init__(self, num_workers: int = 2):
        self._queue: Queue = Queue(maxsize=Config.PROCESSING_QUEUE_SIZE)
        self._workers: List[threading.Thread] = []
        self._shutdown = threading.Event()
        self._num_workers = num_workers
    
    def enqueue(self, item) -> bool:
        """Enqueue a study or series for processing.
        item can be:
        - str: study_id (backward compatibility)
        - tuple: ('study', study_id) or ('series', series_id)
        """
        try:
            self._queue.put_nowait(item)
            metrics.increment('studies_queued')
            return True
        except:
            metrics.increment('studies_dropped')
            return False
    
    def start_workers(self):
        for i in range(self._num_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f'study-worker-{i}',
                daemon=True
            )
            worker.start()
            self._workers.append(worker)
        logger.info(f"Started {self._num_workers} study workers")
    
    def stop_workers(self):
        self._shutdown.set()
        for _ in self._workers:
            try:
                self._queue.put_nowait(None)
            except:
                pass
        for w in self._workers:
            w.join(timeout=5)
        self._workers.clear()
    
    def _worker_loop(self):
        while not self._shutdown.is_set():
            try:
                item = self._queue.get(timeout=1)
                if item is None:
                    break
                if not Config.ROUTER_ENABLED:
                    self._queue.task_done()
                    continue
                
                # Handle both old format (str) and new format (tuple)
                if isinstance(item, tuple):
                    resource_type, resource_id = item
                    if resource_type == 'series':
                        process_series(resource_id)
                    else:
                        process_study(resource_id)
                else:
                    # Backward compatibility: treat as study
                    process_study(item)
                
                self._queue.task_done()
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            'queue_size': self._queue.qsize(),
            'max_size': Config.PROCESSING_QUEUE_SIZE,
            'workers': len(self._workers)
        }


study_queue = StudyProcessingQueue(Config.PROCESSING_WORKERS)


# =============================================================================
# RULES ENGINE
# =============================================================================

DICOM_TAG_MAP = {
    '(0008,1030)': 'StudyDescription',
    '(0008,0020)': 'StudyDate',
    '(0008,0030)': 'StudyTime',
    '(0008,0050)': 'AccessionNumber',
    '(0008,0061)': 'ModalitiesInStudy',
    '(0020,000d)': 'StudyInstanceUID',
    '(0020,0010)': 'StudyID',
    '(0010,0010)': 'PatientName',
    '(0010,0020)': 'PatientID',
    '(0010,0030)': 'PatientBirthDate',
    '(0010,0040)': 'PatientSex',
    '(0008,0060)': 'Modality',
    '(0008,103e)': 'SeriesDescription',
    '(0020,000e)': 'SeriesInstanceUID',
    '(0020,0011)': 'SeriesNumber',
    '(0008,0070)': 'Manufacturer',
    '(0008,0080)': 'InstitutionName',
    '(0008,1010)': 'StationName',
    '(0008,1090)': 'ManufacturerModelName',
    '(0008,0090)': 'ReferringPhysicianName',
    '(0008,1050)': 'PerformingPhysicianName',
    '(0018,0015)': 'BodyPartExamined',
    '(0018,1030)': 'ProtocolName',
    '(0032,1060)': 'RequestedProcedureDescription',
}


@lru_cache(maxsize=256)
def get_tag_name(dicom_tag: str) -> Optional[str]:
    return DICOM_TAG_MAP.get(dicom_tag.lower())


@dataclass
class SimpleRule:
    modality: str
    destinations: List[str]
    description: str = ""
    condition_type: Optional[str] = None
    dicom_tag: Optional[str] = None
    tag_value: Optional[str] = None
    source_aet: Optional[str] = None
    enabled: bool = True
    match_count: int = 0
    
    def __post_init__(self):
        self.modality = self.modality.upper().strip()
        self.destinations = [d.upper().strip() for d in self.destinations if d.strip()]
        if not self.description:
            self.description = self._generate_description()
    
    def _generate_description(self) -> str:
        desc = f"Forward ALL {self.modality}"
        if self.condition_type:
            if self.condition_type in ('FROM', 'notFROM'):
                desc += f" {self.condition_type} {self.source_aet}"
            elif self.dicom_tag and self.tag_value is not None:
                desc += f" {self.condition_type} {self.dicom_tag} \"{self.tag_value}\""
        desc += f" to {', '.join(self.destinations)}"
        return desc
    
    def validate(self) -> Tuple[bool, str]:
        if not self.modality:
            return False, "Modality is required"
        if not self.destinations:
            return False, "At least one destination is required"
        if len(self.destinations) > 10:
            return False, "Too many destinations (max 10)"
        if self.condition_type in ('IfTagEqual', 'IfTagNotEqual', 'IfTagContains', 'IfTagNotContains'):
            if not self.dicom_tag:
                return False, "DICOM tag is required"
            if self.tag_value is None:
                return False, "Tag value is required"
            if not get_tag_name(self.dicom_tag):
                return False, f"Unknown tag: {self.dicom_tag}"
        if self.condition_type in ('FROM', 'notFROM') and not self.source_aet:
            return False, "Source AET is required"
        return True, ""
    
    def matches(self, study_data: Dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        if self.modality != "ALL":
            modalities = study_data.get('ModalitiesInStudy', [])
            if isinstance(modalities, str):
                modalities = modalities.split('\\')
            if self.modality not in [m.upper() for m in modalities]:
                return False
        
        if self.condition_type in ('FROM', 'notFROM'):
            remote_aet = study_data.get('RemoteAET', '').upper()
            expected = (self.source_aet or '').upper()
            if self.condition_type == 'FROM' and remote_aet != expected:
                return False
            if self.condition_type == 'notFROM' and remote_aet == expected:
                return False
        
        if self.condition_type in ('IfTagEqual', 'IfTagNotEqual', 'IfTagContains', 'IfTagNotContains'):
            tag_name = get_tag_name(self.dicom_tag)
            if not tag_name:
                return False
            actual = str(study_data.get(tag_name, '')).upper()
            expected = str(self.tag_value or '').upper()
            if self.condition_type == 'IfTagEqual' and actual != expected:
                return False
            if self.condition_type == 'IfTagNotEqual' and actual == expected:
                return False
            if self.condition_type == 'IfTagContains' and expected not in actual:
                return False
            if self.condition_type == 'IfTagNotContains' and expected in actual:
                return False
        
        self.match_count += 1
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'modality': self.modality,
            'destinations': self.destinations,
            'description': self.description,
            'condition_type': self.condition_type,
            'dicom_tag': self.dicom_tag,
            'tag_value': self.tag_value,
            'source_aet': self.source_aet,
            'enabled': self.enabled,
            'match_count': self.match_count
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'SimpleRule':
        return SimpleRule(
            modality=data.get('modality', 'ALL'),
            destinations=data.get('destinations', []),
            description=data.get('description', ''),
            condition_type=data.get('condition_type'),
            dicom_tag=data.get('dicom_tag'),
            tag_value=data.get('tag_value'),
            source_aet=data.get('source_aet'),
            enabled=data.get('enabled', True),
            match_count=data.get('match_count', 0)
        )


class RulesManager:
    def __init__(self):
        self._rules: List[SimpleRule] = []
        self._lock = threading.RLock()
        self._version = 0
    
    @property
    def rules(self) -> List[SimpleRule]:
        with self._lock:
            return list(self._rules)
    
    @property
    def version(self) -> int:
        with self._lock:
            return self._version
    
    def add_rule(self, rule: SimpleRule) -> Tuple[bool, str]:
        is_valid, error = rule.validate()
        if not is_valid:
            return False, error
        with self._lock:
            if len(self._rules) >= Config.MAX_RULES:
                return False, f"Maximum rules limit reached ({Config.MAX_RULES})"
            self._rules.append(rule)
            self._version += 1
            logger.info(f"Rule added: {rule.description}")
            return True, "Rule added successfully"
    
    def update_rules(self, rules: List[SimpleRule]) -> Tuple[bool, str]:
        if len(rules) > Config.MAX_RULES:
            return False, f"Too many rules (max {Config.MAX_RULES})"
        for i, rule in enumerate(rules):
            is_valid, error = rule.validate()
            if not is_valid:
                return False, f"Rule {i}: {error}"
        with self._lock:
            self._rules = rules
            self._version += 1
            logger.info(f"Rules updated: {len(rules)} rules")
            return True, f"Updated {len(rules)} rules"
    
    def delete_rule(self, index: int) -> Tuple[bool, str]:
        with self._lock:
            if 0 <= index < len(self._rules):
                rule = self._rules.pop(index)
                self._version += 1
                logger.info(f"Rule deleted: {rule.description}")
                return True, "Rule deleted"
            return False, "Invalid rule index"
    
    def evaluate(self, study_data: Dict[str, Any]) -> Set[str]:
        destinations = set()
        matched_rules = []
        with self._lock:
            for rule in self._rules:
                try:
                    if rule.matches(study_data):
                        destinations.update(rule.destinations)
                        matched_rules.append(rule.description)
                        logger.info(f"Rule matched: {rule.description}")
                    else:
                        logger.debug(f"Rule not matched: {rule.description}")
                except Exception as e:
                    logger.warning(f"Error evaluating rule {rule.description}: {e}")
            if matched_rules:
                logger.info(f"Total matched rules: {len(matched_rules)}")
            else:
                logger.info("No rules matched")
        return destinations
    
    def save_to_file(self, filepath: str) -> bool:
        with self._lock:
            try:
                ensure_directory(filepath)
                rules_data = [r.to_dict() for r in self._rules]
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(rules_data, f, indent=2, ensure_ascii=False)
                logger.info(f"Rules saved to {filepath}")
                return True
            except Exception as e:
                logger.error(f"Failed to save rules: {e}")
                return False
    
    def load_from_file(self, filepath: str) -> bool:
        if not os.path.exists(filepath):
            logger.info(f"Rules file not found: {filepath}")
            return False
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                rules_data = json.load(f)
            rules = [SimpleRule.from_dict(r) for r in rules_data]
            success, message = self.update_rules(rules)
            if success:
                logger.info(f"Loaded {len(rules)} rules")
            else:
                logger.error(f"Failed to load rules: {message}")
            return success
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            counts = defaultdict(int)
            for r in self._rules:
                counts[r.modality] += 1
            return {
                'count': len(self._rules),
                'version': self._version,
                'by_modality': dict(counts),
                'total_matches': sum(r.match_count for r in self._rules)
            }


rules_manager = RulesManager()


# =============================================================================
# CONNECTIVITY CHECKER
# =============================================================================

class ConnectivityChecker:
    __slots__ = ['_cache', '_lock', '_stats']
    
    def __init__(self):
        self._cache: Dict[str, Tuple[bool, datetime, str]] = {}
        self._lock = threading.Lock()
        self._stats = defaultdict(int)
    
    @timed('connectivity_check')
    def check(self, modality: str, use_cache: bool = True) -> Tuple[bool, str]:
        self._stats['total_checks'] += 1
        with self._lock:
            if use_cache and modality in self._cache:
                is_ok, cached_at, error = self._cache[modality]
                if datetime.utcnow() - cached_at < timedelta(seconds=Config.ECHO_CACHE_TTL):
                    self._stats['cache_hits'] += 1
                    return is_ok, error
        
        is_ok, error = self._perform_echo(modality)
        with self._lock:
            self._cache[modality] = (is_ok, datetime.utcnow(), error)
            if is_ok:
                self._stats['successful'] += 1
            else:
                self._stats['failed'] += 1
        return is_ok, error
    
    def _perform_echo(self, modality: str) -> Tuple[bool, str]:
        try:
            payload = json.dumps({"Timeout": Config.ECHO_TIMEOUT})
            orthanc.RestApiPost(f'/modalities/{modality}/echo', payload)
            return True, ""
        except Exception as e:
            return False, str(e)
    
    def invalidate(self, modality: str = None):
        with self._lock:
            if modality:
                self._cache.pop(modality, None)
            else:
                self._cache.clear()
    
    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)


connectivity_checker = ConnectivityChecker()


# =============================================================================
# STUDY PROCESSING
# =============================================================================

def expand_dicom_attributes(data: Dict[str, Any]) -> Dict[str, Any]:
    result = {}
    for key, value in data.items():
        if value is None:
            result[key] = None
        elif isinstance(value, str):
            if value.isdigit() and len(value) == 8:
                try:
                    result[key] = int(value)
                    continue
                except:
                    pass
            if '\\' in value:
                result[key] = value.split('\\')
                continue
            result[key] = value
        else:
            result[key] = value
    return result


@timed('forward_study')
def forward_to_modality(modality: str, resource_id: str):
    """Forward study with circuit breaker protection."""
    # Check circuit breaker first
    if not circuit_breaker.can_call(modality):
        raise Exception(f"Circuit breaker open for {modality}")
    
    try:
        payload = json.dumps({
            "Asynchronous": Config.ASYNC_FORWARD,
            "Compress": Config.COMPRESS,
            "Permissive": True,
            "Resources": [resource_id],
            "Synchronous": not Config.ASYNC_FORWARD,
            "MoveOriginatorAet": Config.MOVE_ORIGINATOR_AET,
            "MoveOriginatorID": Config.MOVE_ORIGINATOR_ID,
            "StorageCommitment": Config.STORAGE_COMMITMENT
        })
        orthanc.RestApiPost(f'/modalities/{modality}/store', payload)
        logger.info(f"Forwarded {resource_id[:20]}... to {modality}")
        metrics.increment('studies_forwarded')
        
        # Record success for circuit breaker
        circuit_breaker.record_success(modality)
        
    except Exception as e:
        # Record failure for circuit breaker
        circuit_breaker.record_failure(modality)
        raise


@timed('process_study')
def process_study(resource_id: str):
    metrics.increment('studies_processed')
    try:
        study_response = orthanc.RestApiGet(f'/studies/{resource_id}')
        study = safe_json_loads(study_response, {})
        
        if not study:
            logger.error(f"Could not load study {resource_id[:20]}")
            return
        
        patient_tags = study.get('PatientMainDicomTags', {})
        patient_name = patient_tags.get('PatientName', 'Unknown')
        patient_id = patient_tags.get('PatientID', 'Unknown')
        
        # Log only masked version for HIPAA
        logger.info(f"Processing study: PatientID={patient_id[:3]}***, ID={resource_id[:20]}...")
        
        study_data = expand_dicom_attributes({
            **study.get('MainDicomTags', {}),
            **patient_tags,
            **study.get('RequestedTags', {})
        })
        
        series_list = study.get('Series', [])
        
        try:
            if series_list:
                series_resp = orthanc.RestApiGet(f'/series/{series_list[0]}')
                series = safe_json_loads(series_resp, {})
                instances = series.get('Instances', [])
                if instances:
                    meta_resp = orthanc.RestApiGet(f'/instances/{instances[0]}/metadata?expand')
                    metadata = safe_json_loads(meta_resp, {})
                    remote_aet = metadata.get('RemoteAET') or metadata.get('CalledAET', '')
                    if remote_aet:
                        study_data['RemoteAET'] = remote_aet
        except Exception as e:
            logger.debug(f"Could not get RemoteAET: {e}")
        
        if not study_data.get('ModalitiesInStudy'):
            try:
                modalities_set = set()
                for series_id in series_list:
                    series_resp = orthanc.RestApiGet(f'/series/{series_id}')
                    series_info = safe_json_loads(series_resp, {})
                    modality = series_info.get('MainDicomTags', {}).get('Modality')
                    if modality:
                        modalities_set.add(modality.upper())
                if modalities_set:
                    study_data['ModalitiesInStudy'] = list(modalities_set)
            except Exception as e:
                logger.debug(f"Could not get modalities: {e}")
        
        destinations = rules_manager.evaluate(study_data)
        
        if not destinations:
            logger.info(f"No matching rules for study {resource_id[:20]}")
            return
        
        logger.info(f"Routing study {resource_id[:20]}... to: {', '.join(destinations)}")
        
        metrics.add_history({
            'study_id': resource_id,
            'patient': '***',  # Masked for logs
            'destinations': list(destinations),
            'status': 'processing'
        })
        
        modalities = study_data.get('ModalitiesInStudy', '')
        if isinstance(modalities, list):
            modality_str = '\\'.join(modalities)
        else:
            modality_str = str(modalities)
        
        for dest in destinations:
            if Config.CONNECTIVITY_CHECK_ENABLED:
                is_ok, error = connectivity_checker.check(dest)
                if not is_ok:
                    logger.warning(f"Connectivity check failed for {dest}, deferring")
                    deferred_queue.add(resource_id, dest, error, patient_name, modality_str)
                    continue
            
            try:
                forward_to_modality(dest, resource_id)
            except Exception as e:
                logger.error(f"Forward failed to {dest}: {str(e)[:100]}")
                deferred_queue.add(resource_id, dest, str(e), patient_name, modality_str)
    
    except Exception as e:
        logger.error(f"Error processing study {resource_id[:20]}: {e}")
        logger.debug(traceback.format_exc())
        metrics.increment('studies_errors')


@timed('process_series')
def process_series(series_id: str):
    """Process a stable series (for series-level routing mode).
    
    In series mode, each series is routed independently as soon as it stabilizes.
    This provides faster routing but may result in multiple C-MOVE operations
    for the same study if multiple series arrive.
    """
    metrics.increment('series_processed')
    try:
        # Get series info
        series_response = orthanc.RestApiGet(f'/series/{series_id}')
        series = safe_json_loads(series_response, {})
        
        if not series:
            logger.error(f"Could not load series {series_id[:20]}")
            return
        
        # Get parent study info
        parent_study_id = series.get('ParentStudy')
        if not parent_study_id:
            logger.error(f"Series {series_id[:20]} has no parent study")
            return
        
        # Get study info for patient data
        study_response = orthanc.RestApiGet(f'/studies/{parent_study_id}')
        study = safe_json_loads(study_response, {})
        
        if not study:
            logger.error(f"Could not load parent study for series {series_id[:20]}")
            return
        
        patient_tags = study.get('PatientMainDicomTags', {})
        patient_name = patient_tags.get('PatientName', 'Unknown')
        patient_id = patient_tags.get('PatientID', 'Unknown')
        
        # Log only masked version for HIPAA
        logger.info(f"Processing series: PatientID={patient_id[:3]}***, SeriesID={series_id[:20]}...")
        
        # Build data for rule evaluation
        series_data = expand_dicom_attributes({
            **series.get('MainDicomTags', {}),
            **study.get('MainDicomTags', {}),
            **patient_tags,
        })
        
        # Get modality from series
        series_modality = series.get('MainDicomTags', {}).get('Modality', '')
        if series_modality:
            series_data['ModalitiesInStudy'] = [series_modality.upper()]
        
        # Get RemoteAET from first instance
        try:
            instances = series.get('Instances', [])
            if instances:
                meta_resp = orthanc.RestApiGet(f'/instances/{instances[0]}/metadata?expand')
                metadata = safe_json_loads(meta_resp, {})
                remote_aet = metadata.get('RemoteAET') or metadata.get('CalledAET', '')
                if remote_aet:
                    series_data['RemoteAET'] = remote_aet
        except Exception as e:
            logger.debug(f"Could not get RemoteAET for series: {e}")
        
        # Evaluate rules
        destinations = rules_manager.evaluate(series_data)
        
        if not destinations:
            logger.info(f"No matching rules for series {series_id[:20]}")
            return
        
        logger.info(f"Routing series {series_id[:20]}... to: {', '.join(destinations)}")
        
        metrics.add_history({
            'series_id': series_id,
            'study_id': parent_study_id,
            'patient': '***',  # Masked for logs
            'destinations': list(destinations),
            'status': 'processing',
            'modality': series_modality
        })
        
        # Route to destinations
        modality_str = series_modality or 'Unknown'
        
        for dest in destinations:
            if Config.CONNECTIVITY_CHECK_ENABLED:
                is_ok, error = connectivity_checker.check(dest)
                if not is_ok:
                    logger.warning(f"Connectivity check failed for {dest}, deferring series")
                    deferred_queue.add(series_id, dest, error, patient_name, modality_str)
                    continue
            
            try:
                # For series mode, we forward the series (not the whole study)
                forward_to_modality(dest, series_id)
            except Exception as e:
                logger.error(f"Forward failed to {dest}: {str(e)[:100]}")
                deferred_queue.add(series_id, dest, str(e), patient_name, modality_str)
    
    except Exception as e:
        logger.error(f"Error processing series {series_id[:20]}: {e}")
        logger.debug(traceback.format_exc())
        metrics.increment('series_errors')


# =============================================================================
# ORTHANC CALLBACK
# =============================================================================

def OnChange(changeType, level, resourceId):
    # Check if router is enabled
    if not Config.ROUTER_ENABLED:
        return
    
    # Handle based on stable mode configuration
    if Config.STABLE_MODE == 'series':
        # In series mode: process each series as it stabilizes
        if changeType == orthanc.ChangeType.STABLE_SERIES:
            if not study_queue.enqueue(('series', resourceId)):
                logger.warning(f"Failed to queue series {resourceId}")
        return
    else:
        # Default study mode: wait for complete study
        if changeType == orthanc.ChangeType.STABLE_STUDY:
            if not study_queue.enqueue(('study', resourceId)):
                logger.warning(f"Failed to queue study {resourceId}")


# =============================================================================
# REST API HANDLERS
# =============================================================================

# Load HTML from external file
def get_web_ui_html() -> str:
    """Load Web UI from external HTML file."""
    # Look for web-ui.html in same directory as script
    script_dir = get_plugin_directory()
    html_path = os.path.join(script_dir, 'web-ui.html')
    
    if os.path.exists(html_path):
        try:
            with open(html_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Cannot load web-ui.html: {e}")
    
    # Fallback error message if file not found
    return """<!DOCTYPE html>
    <html><body>
    <h1>Error: web-ui.html not found</h1>
    <p>Please ensure web-ui.html is in the same directory as the Python script.</p>
    <p>Expected location: """ + html_path + """</p>
    </body></html>"""


def WebUICallback(output, uri, **request):
    html = get_web_ui_html()
    output.AnswerBuffer(html.encode('utf-8'), 'text/html')


def HealthCallback(output, uri, **request):
    # Deep health check
    db_status = 'ok'
    try:
        if db_manager:
            db_manager.get_processed_count()
    except Exception as e:
        db_status = f'error: {str(e)}'
    
    disk_ok = True
    try:
        stat = os.statvfs(Config.DATA_DIR)
        free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
        if free_gb < 1:
            disk_ok = False
    except:
        pass
    
    response = {
        'status': 'healthy' if db_status == 'ok' and disk_ok else 'degraded',
        'checks': {
            'database': db_status,
            'disk_space': 'ok' if disk_ok else 'low',
            'router_enabled': Config.ROUTER_ENABLED,
        },
        'version': __version__,
        'timestamp': datetime.utcnow().isoformat(),
        'platform': f"{platform.system()} {platform.release()}",
        'python': f"{sys.version_info.major}.{sys.version_info.minor}",
        'router_enabled': Config.ROUTER_ENABLED,
        'rules': rules_manager.get_stats(),
        'connectivity': {'stats': connectivity_checker.get_stats()},
        'circuit_breaker': circuit_breaker.get_status(),
        'deferred': deferred_queue.get_stats(),
        'processing': study_queue.get_stats(),
        'watchfolder': watch_folder_manager.get_status() if watch_folder_manager else {'enabled': False},
        'metrics': metrics.get_stats()
    }
    output.AnswerBuffer(json.dumps(response, indent=2).encode('utf-8'), 'application/json')


def RulesCallback(output, uri, **request):
    method = request.get('method', 'GET')
    if method == 'GET':
        response = {
            'rules': [r.to_dict() for r in rules_manager.rules],
            'version': rules_manager.version,
            'count': len(rules_manager.rules)
        }
        output.AnswerBuffer(json.dumps(response, indent=2).encode('utf-8'), 'application/json')
        return
    if method == 'POST':
        if not rate_limited(output, lambda: True):
            return
        try:
            body = request.get('body', b'')
            if isinstance(body, bytes):
                body = body.decode('utf-8')
            rules_data = json.loads(body)
            rules = [SimpleRule.from_dict(r) for r in rules_data]
            success, message = rules_manager.update_rules(rules)
            if success:
                rules_manager.save_to_file(Config.RULES_FILE_PATH)
                output.AnswerBuffer(json.dumps({'success': True, 'message': message}).encode('utf-8'), 'application/json')
            else:
                output.SendHttpStatus(400, json.dumps({'success': False, 'error': message}))
        except Exception as e:
            output.SendHttpStatus(400, json.dumps({'success': False, 'error': str(e)}))
        return
    output.SendMethodNotAllowed('GET,POST')


def ConfigCallback(output, uri, **request):
    method = request.get('method', 'GET')
    if method == 'GET':
        output.AnswerBuffer(json.dumps(Config.to_dict(), indent=2).encode('utf-8'), 'application/json')
        return
    if method == 'POST':
        try:
            body = request.get('body', b'')
            if isinstance(body, bytes):
                body = body.decode('utf-8')
            updates = json.loads(body)
            changed = Config.update(updates)
            output.AnswerBuffer(json.dumps({
                'success': True,
                'message': f"Updated: {', '.join(changed)}" if changed else "No changes",
                'changed': changed
            }).encode('utf-8'), 'application/json')
        except Exception as e:
            output.SendHttpStatus(400, json.dumps({'success': False, 'error': str(e)}))
        return
    output.SendMethodNotAllowed('GET,POST')


def LogsCallback(output, uri, **request):
    limit = 100
    level = None
    groups = request.get('groups', [])
    for g in groups:
        if g.startswith('limit='):
            try:
                limit = int(g.split('=')[1])
            except:
                pass
        elif g.startswith('level='):
            level = g.split('=')[1]
            if level == 'ALL':
                level = None
    logs = log_buffer.get_recent(limit, level)
    output.AnswerBuffer(json.dumps({'logs': logs, 'count': len(logs)}).encode('utf-8'), 'application/json')


def DeferredCallback(output, uri, **request):
    method = request.get('method', 'GET')
    if method == 'GET':
        output.AnswerBuffer(json.dumps({
            'tasks': deferred_queue.get_all(),
            'stats': deferred_queue.get_stats()
        }, indent=2).encode('utf-8'), 'application/json')
        return
    if method == 'DELETE':
        count = deferred_queue.clear()
        output.AnswerBuffer(json.dumps({'success': True, 'cleared': count}).encode('utf-8'), 'application/json')
        return
    output.SendMethodNotAllowed('GET,DELETE')


def ControlCallback(output, uri, **request):
    if request.get('method') != 'POST':
        output.SendMethodNotAllowed('POST')
        return
    try:
        body = request.get('body', b'')
        if isinstance(body, bytes):
            body = body.decode('utf-8')
        data = json.loads(body)
        action = data.get('action', '').lower()
        if action == 'start':
            Config.ROUTER_ENABLED = True
            study_queue.start_workers()
            deferred_queue.start_worker()
            if watch_folder_manager and not watch_folder_manager.is_alive():
                watch_folder_manager.start()
            message = "Router started"
        elif action == 'stop':
            Config.ROUTER_ENABLED = False
            if watch_folder_manager:
                watch_folder_manager.stop()
            message = "Router stopped"
        elif action == 'restart':
            Config.ROUTER_ENABLED = False
            study_queue.stop_workers()
            deferred_queue.stop_worker()
            if watch_folder_manager:
                watch_folder_manager.stop()
            time.sleep(1)
            Config.ROUTER_ENABLED = True
            study_queue.start_workers()
            deferred_queue.start_worker()
            if watch_folder_manager:
                watch_folder_manager.start()
            message = "Router restarted"
        else:
            output.SendHttpStatus(400, json.dumps({'success': False, 'error': 'Invalid action'}))
            return
        logger.info(message)
        output.AnswerBuffer(json.dumps({'success': True, 'message': message}).encode('utf-8'), 'application/json')
    except Exception as e:
        output.SendHttpStatus(400, json.dumps({'success': False, 'error': str(e)}))


def WatchFolderCallback(output, uri, **request):
    method = request.get('method', 'GET')
    if method == 'GET':
        status = watch_folder_manager.get_status() if watch_folder_manager else {'enabled': False}
        output.AnswerBuffer(json.dumps(status, indent=2).encode('utf-8'), 'application/json')
        return
    if method == 'POST':
        try:
            body = request.get('body', b'')
            if isinstance(body, bytes):
                body = body.decode('utf-8')
            updates = json.loads(body)
            
            if 'WATCH_FOLDER_PATH' in updates:
                new_path = updates['WATCH_FOLDER_PATH']
                need_write = updates.get('WATCH_FOLDER_DELETE_ORIGINALS', Config.WATCH_FOLDER_DELETE_ORIGINALS)
                is_valid, error = validate_path(new_path, need_write)
                if not is_valid:
                    output.SendHttpStatus(400, json.dumps({
                        'success': False, 
                        'error': error,
                        'validation_failed': True
                    }))
                    return
            
            changed = Config.update(updates)
            output.AnswerBuffer(json.dumps({
                'success': True,
                'message': f"Updated: {', '.join(changed)}" if changed else "No changes",
                'changed': changed
            }).encode('utf-8'), 'application/json')
        except Exception as e:
            output.SendHttpStatus(400, json.dumps({'success': False, 'error': str(e)}))
        return
    output.SendMethodNotAllowed('GET,POST')


def WatchFolderScanCallback(output, uri, **request):
    if request.get('method') != 'POST':
        output.SendMethodNotAllowed('POST')
        return
    try:
        if watch_folder_manager:
            watch_folder_manager.trigger_scan()
            output.AnswerBuffer(json.dumps({'success': True, 'message': 'Scan triggered'}).encode('utf-8'), 'application/json')
        else:
            output.SendHttpStatus(503, json.dumps({'success': False, 'error': 'Watch Folder not initialized'}))
    except Exception as e:
        output.SendHttpStatus(500, json.dumps({'success': False, 'error': str(e)}))


def WatchFolderLogsCallback(output, uri, **request):
    logs = metrics.get_watch_folder_logs(50)
    output.AnswerBuffer(json.dumps({'logs': logs}).encode('utf-8'), 'application/json')


# =============================================================================
# SIGNAL HANDLERS (GRACEFUL SHUTDOWN)
# =============================================================================

def setup_signal_handlers():
    """Handle SIGTERM/SIGINT for graceful shutdown."""
    def signal_handler(signum, frame):
        sig_name = 'SIGTERM' if signum == signal.SIGTERM else 'SIGINT'
        logger.info(f"Received {sig_name}, starting graceful shutdown...")
        
        # Stop accepting new work
        Config.ROUTER_ENABLED = False
        
        # Stop watch folder
        if watch_folder_manager:
            watch_folder_manager._shutdown.set()
        
        # Wait a bit for current tasks
        time.sleep(2)
        
        # Cleanup
        cleanup()
        
        logger.info("Graceful shutdown complete")
        sys.exit(0)
    
    try:
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        logger.info("Signal handlers registered for graceful shutdown")
    except Exception as e:
        logger.warning(f"Cannot register signal handlers: {e}")


# =============================================================================
# INITIALIZATION
# =============================================================================

def cleanup():
    logger.info("Shutting down DICOM Router...")
    try:
        study_queue.stop_workers()
        deferred_queue.stop_worker()
        if watch_folder_manager:
            watch_folder_manager.stop()
        rules_manager.save_to_file(Config.RULES_FILE_PATH)
        if db_manager:
            db_manager.close()
    except Exception as e:
        logger.error(f"Cleanup error: {e}")
    logger.info("Shutdown complete")


def initialize():
    global watch_folder_manager, db_manager
    
    logger.info("=" * 70)
    logger.info(f"Orthanc DICOM Router v{__version__} (Secure & Optimized)")
    logger.info("=" * 70)
    
    # Security check
    security_check()
    
    # Initialize Database with WAL mode
    ensure_directory(Config.DB_PATH)
    db_manager = DatabaseManager(Config.DB_PATH)
    
    # Migrate old JSON data
    old_json = Config.WATCH_FOLDER_DB_PATH
    db_manager.migrate_from_json(old_json)
    
    # Load persisted settings
    Config.load_from_db()
    
    logger.info(f"Platform: {platform.system()} {platform.release()}")
    logger.info(f"Database: {Config.DB_PATH} (WAL mode)")
    logger.info(f"Data directory: {Config.DATA_DIR}")
    logger.info(f"Processing workers: {Config.PROCESSING_WORKERS}")
    logger.info(f"Log level: {Config.LOG_LEVEL}")
    logger.info(f"PHI Filtering: {'Enabled (HIPAA compliant)' if hasattr(logger.filters[0], 'PHI_PATTERNS') else 'Disabled'}")
    
    # Setup signal handlers
    setup_signal_handlers()
    
    # Initialize components
    if not rules_manager.load_from_file(Config.RULES_FILE_PATH):
        logger.info("Creating default rules...")
        rules_manager.add_rule(SimpleRule("CT", ["PACS"], "Forward ALL CT to PACS"))
        rules_manager.add_rule(SimpleRule("MR", ["PACS"], "Forward ALL MR to PACS"))
        rules_manager.save_to_file(Config.RULES_FILE_PATH)
    
    study_queue.start_workers()
    deferred_queue.start_worker()
    
    watch_folder_manager = WatchFolderManager()
    
    if Config.WATCH_FOLDER_ENABLED:
        is_valid, msg = validate_path(Config.WATCH_FOLDER_PATH, Config.WATCH_FOLDER_DELETE_ORIGINALS)
        if is_valid:
            watch_folder_manager.start()
            logger.info(f"Watch Folder: started monitoring {Config.WATCH_FOLDER_PATH}")
        else:
            logger.error(f"Watch Folder: cannot start - {msg}")
    
    logger.info(f"Loaded {len(rules_manager.rules)} rules")
    logger.info(f"Circuit Breaker: threshold={circuit_breaker.failure_threshold}, recovery={circuit_breaker.recovery_timeout}s")
    logger.info("=" * 70)
    logger.info("Web UI: http://localhost:8042/dicom-router/")
    logger.info("=" * 70)


atexit.register(cleanup)

orthanc.RegisterOnChangeCallback(OnChange)

orthanc.RegisterRestCallback('/dicom-router', WebUICallback)
orthanc.RegisterRestCallback('/dicom-router/', WebUICallback)

orthanc.RegisterRestCallback('/dicom-router/health', HealthCallback)
orthanc.RegisterRestCallback('/dicom-router/rules', RulesCallback)
orthanc.RegisterRestCallback('/dicom-router/config', ConfigCallback)
orthanc.RegisterRestCallback('/dicom-router/logs', LogsCallback)
orthanc.RegisterRestCallback('/dicom-router/deferred', DeferredCallback)
orthanc.RegisterRestCallback('/dicom-router/control', ControlCallback)

orthanc.RegisterRestCallback('/dicom-router/watchfolder', WatchFolderCallback)
orthanc.RegisterRestCallback('/dicom-router/watchfolder/scan', WatchFolderScanCallback)
orthanc.RegisterRestCallback('/dicom-router/watchfolder/logs', WatchFolderLogsCallback)

initialize()