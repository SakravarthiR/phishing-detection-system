"""
PhishTank integration - pulls down their verified phishing URL database.

Updates every 6 hours automatically. The database is huge (15k+ URLs) so I cache
it locally. This gives us instant lookup for known threats without hammering their API.

Pretty cool addition tbh, catches a lot of stuff the ML model might miss.
"""

import requests
import json
import time
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import logging

logger = logging.getLogger(__name__)


class PhishTankDB:
    """
    PhishTank Database Handler
    Downloads, caches, and queries PhishTank's verified phishing database
    """
    
    # PhishTank API endpoints
    PHISHTANK_API_URL = "http://data.phishtank.com/data/online-valid.json"
    PHISHTANK_FALLBACK_URL = "https://phishtank.org/data/online-valid.json.gz"
    CACHE_FILE = "phishtank_cache.json"
    CACHE_DURATION_HOURS = 6  # Refresh every 6 hours
    
    def __init__(self, cache_dir: str = None):
        """
        Initialize PhishTank database handler
        
        Args:
            cache_dir: Directory to store cache file (default: current directory)
        """
        self.cache_dir = cache_dir or os.path.dirname(__file__)
        self.cache_path = os.path.join(self.cache_dir, self.CACHE_FILE)
        self.database: List[Dict] = []
        self.url_set: set = set()
        self.last_update: Optional[datetime] = None
        
        # Try to load from cache
        self._load_cache()
    
    def _load_cache(self) -> bool:
        """Load database from cache file if it exists and is fresh"""
        try:
            if not os.path.exists(self.cache_path):
                logger.info("No PhishTank cache found")
                return False
            
            # Check cache age
            cache_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(self.cache_path))
            if cache_age > timedelta(hours=self.CACHE_DURATION_HOURS):
                logger.info(f"PhishTank cache is stale (age: {cache_age})")
                return False
            
            # Load cache
            with open(self.cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.database = data.get('entries', [])
                self.last_update = datetime.fromisoformat(data.get('last_update'))
                self.url_set = set(entry['url'].lower() for entry in self.database)
            
            logger.info(f"✅ Loaded {len(self.database)} PhishTank entries from cache")
            return True
            
        except Exception as e:
            logger.error(f"Error loading PhishTank cache: {e}")
            return False
    
    def _save_cache(self) -> bool:
        """Save database to cache file"""
        try:
            cache_data = {
                'last_update': datetime.now().isoformat(),
                'entry_count': len(self.database),
                'entries': self.database
            }
            
            with open(self.cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f)
            
            logger.info(f"💾 Saved {len(self.database)} entries to PhishTank cache")
            return True
            
        except Exception as e:
            logger.error(f"Error saving PhishTank cache: {e}")
            return False
    
    def update_database(self, force: bool = False) -> bool:
        """
        Download latest PhishTank database
        
        Args:
            force: Force update even if cache is fresh
            
        Returns:
            True if successful, False otherwise
        """
        # Check if update needed
        if not force and self.database:
            cache_age = datetime.now() - self.last_update if self.last_update else timedelta(days=999)
            if cache_age < timedelta(hours=self.CACHE_DURATION_HOURS):
                logger.info("PhishTank cache is still fresh, skipping update")
                return True
        
        try:
            logger.info("📡 Downloading PhishTank database...")
            start_time = time.time()
            
            # Download database
            headers = {
                'User-Agent': 'PhishingDetector/1.0 (Security Research Tool)'
            }
            response = requests.get(self.PHISHTANK_API_URL, headers=headers, timeout=30)
            response.raise_for_status()
            
            # Parse JSON
            self.database = response.json()
            self.url_set = set(entry['url'].lower() for entry in self.database)
            self.last_update = datetime.now()
            
            download_time = time.time() - start_time
            logger.info(f"✅ Downloaded {len(self.database)} PhishTank entries in {download_time:.2f}s")
            
            # Save to cache
            self._save_cache()
            
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Failed to download PhishTank database: {e}")
            return False
        except json.JSONDecodeError as e:
            logger.error(f"❌ Failed to parse PhishTank JSON: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Unexpected error updating PhishTank: {e}")
            return False
    
    def check_url(self, url: str) -> Optional[Dict]:
        """
        Check if URL is in PhishTank database
        
        Args:
            url: URL to check
            
        Returns:
            Dict with phishing info if found, None otherwise
            {
                'is_phishing': True,
                'phish_id': 12345,
                'submission_time': '2025-10-22T10:30:00+00:00',
                'verification_time': '2025-10-22T11:00:00+00:00',
                'target': 'PayPal',
                'details': {...}
            }
        """
        if not self.database:
            # Try to update if empty
            self.update_database()
        
        url_lower = url.lower().strip()
        
        # Quick set lookup
        if url_lower not in self.url_set:
            return None
        
        # Find full entry
        for entry in self.database:
            if entry['url'].lower() == url_lower:
                return {
                    'is_phishing': True,
                    'phish_id': entry.get('phish_id'),
                    'submission_time': entry.get('submission_time'),
                    'verification_time': entry.get('verification_time'),
                    'verified': entry.get('verified', 'yes'),
                    'target': entry.get('target', 'Unknown'),
                    'phish_detail_url': entry.get('phish_detail_url'),
                    'online': entry.get('online', 'yes')
                }
        
        return None
    
    def get_stats(self) -> Dict:
        """Get database statistics"""
        return {
            'total_entries': len(self.database),
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'cache_exists': os.path.exists(self.cache_path),
            'cache_size_mb': os.path.getsize(self.cache_path) / (1024 * 1024) if os.path.exists(self.cache_path) else 0
        }


# Global instance
_phishtank_db: Optional[PhishTankDB] = None


def get_phishtank_db() -> PhishTankDB:
    """Get or create global PhishTank database instance"""
    global _phishtank_db
    if _phishtank_db is None:
        _phishtank_db = PhishTankDB()
        # Try to update on first access
        _phishtank_db.update_database()
    return _phishtank_db


def check_phishtank(url: str) -> Optional[Dict]:
    """
    Convenience function to check URL against PhishTank
    
    Args:
        url: URL to check
        
    Returns:
        Dict with phishing info if found, None otherwise
    """
    db = get_phishtank_db()
    return db.check_url(url)


if __name__ == "__main__":
    # Test the integration
    print("🔍 Testing PhishTank Integration\n")
    
    db = PhishTankDB()
    
    # Update database
    print("Updating database...")
    if db.update_database():
        print(f"✅ Success! Loaded {len(db.database)} entries\n")
    else:
        print("❌ Failed to update database\n")
    
    # Test URLs
    test_urls = [
        "https://www.google.com",  # Should be safe
        "https://www.paypal.com",  # Should be safe
    ]
    
    print("Testing URLs:")
    for url in test_urls:
        result = db.check_url(url)
        if result:
            print(f"❌ PHISHING: {url}")
            print(f"   Target: {result['target']}")
            print(f"   Phish ID: {result['phish_id']}")
        else:
            print(f"✅ SAFE: {url}")
    
    print(f"\n📊 Database Stats:")
    stats = db.get_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
