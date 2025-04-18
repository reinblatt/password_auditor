#!/usr/bin/env python3
"""
Password Auditor - A tool to check if passwords have been compromised using the Have I Been Pwned API.
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import aiohttp
import tqdm
from aiohttp import ClientTimeout
from colorama import Fore, Style, init

# Initialize colorama
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PasswordStrength(Enum):
    """Password strength levels."""
    VERY_WEAK = 0
    WEAK = 1
    MEDIUM = 2
    STRONG = 3
    VERY_STRONG = 4

@dataclass
class PasswordResult:
    """Result of password checking."""
    password: str
    leak_count: int
    strength: PasswordStrength
    error: Optional[str] = None

@dataclass
class Config:
    """Configuration settings for the password auditor."""
    input_file: Path
    batch_size: int = 10
    timeout: int = 10
    rate_limit: float = 0.1
    verbose: bool = False
    cache_file: Optional[Path] = None
    export_file: Optional[Path] = None
    min_strength: PasswordStrength = PasswordStrength.MEDIUM

class PasswordAuditor:
    """Main class for checking passwords against the Have I Been Pwned API."""

    def __init__(self, config: Config):
        """Initialize the password auditor with configuration."""
        self.config = config
        self.base_url = 'https://api.pwnedpasswords.com/range/'
        self.timeout = ClientTimeout(total=config.timeout)
        self.semaphore = asyncio.Semaphore(self.config.batch_size)
        self.rate_limiter = asyncio.Semaphore(1)
        self.cache: Dict[str, int] = self._load_cache()

    def _load_cache(self) -> Dict[str, int]:
        """Load cached results from file."""
        if not self.config.cache_file or not self.config.cache_file.exists():
            return {}
        try:
            with self.config.cache_file.open('r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
            return {}

    def _save_cache(self):
        """Save results to cache file."""
        if not self.config.cache_file:
            return
        try:
            with self.config.cache_file.open('w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")

    @staticmethod
    def hash_password(password: str) -> Tuple[str, str]:
        """Hash a password using SHA-1 and split it into prefix and suffix."""
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        return sha1_hash[:5], sha1_hash[5:]

    @staticmethod
    def check_password_strength(password: str) -> PasswordStrength:
        """Check the strength of a password."""
        score = 0
        
        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1

        # Character variety
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'[0-9]', password):
            score += 1
        if re.search(r'[^A-Za-z0-9]', password):
            score += 1

        # Convert score to strength
        if score >= 5:
            return PasswordStrength.VERY_STRONG
        elif score == 4:
            return PasswordStrength.STRONG
        elif score == 3:
            return PasswordStrength.MEDIUM
        elif score == 2:
            return PasswordStrength.WEAK
        return PasswordStrength.VERY_WEAK

    async def check_password(self, session: aiohttp.ClientSession, password: str) -> PasswordResult:
        """Check a single password against the API."""
        # Check cache first
        if password in self.cache:
            return PasswordResult(
                password=password,
                leak_count=self.cache[password],
                strength=self.check_password_strength(password)
            )

        prefix, suffix = self.hash_password(password)

        async with self.semaphore:
            async with self.rate_limiter:
                await asyncio.sleep(self.config.rate_limit)
                
                try:
                    async with session.get(f"{self.base_url}{prefix}") as response:
                        if response.status != 200:
                            error = f"API error: {response.status} for password prefix {prefix}"
                            logger.error(error)
                            return PasswordResult(
                                password=password,
                                leak_count=-1,
                                strength=self.check_password_strength(password),
                                error=error
                            )

                        text = await response.text()
                        count = self._get_leak_count(text, suffix)
                        
                        # Cache the result
                        self.cache[password] = count
                        
                        return PasswordResult(
                            password=password,
                            leak_count=count,
                            strength=self.check_password_strength(password)
                        )

                except aiohttp.ClientError as e:
                    error = f"Network error while checking password: {e}"
                    logger.error(error)
                    return PasswordResult(
                        password=password,
                        leak_count=-1,
                        strength=self.check_password_strength(password),
                        error=error
                    )
                except Exception as e:
                    error = f"Unexpected error while checking password: {e}"
                    logger.error(error)
                    return PasswordResult(
                        password=password,
                        leak_count=-1,
                        strength=self.check_password_strength(password),
                        error=error
                    )

    @staticmethod
    def _get_leak_count(response_text: str, hash_suffix: str) -> int:
        """Get the number of times a password has been leaked."""
        for line in response_text.splitlines():
            suffix, count = line.split(':')
            if suffix == hash_suffix:
                return int(count)
        return 0

    async def check_passwords(self, passwords: List[str]) -> List[PasswordResult]:
        """Check multiple passwords concurrently."""
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            tasks = [self.check_password(session, password) for password in passwords]
            
            if self.config.verbose:
                results = []
                with tqdm.tqdm(total=len(tasks), desc="Checking passwords") as pbar:
                    for task in asyncio.as_completed(tasks):
                        result = await task
                        results.append(result)
                        pbar.update(1)
                return results
            else:
                return await asyncio.gather(*tasks)

    def export_results(self, results: List[PasswordResult]):
        """Export results to file."""
        if not self.config.export_file:
            return

        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'results': [
                    {
                        'password': result.password,
                        'leak_count': result.leak_count,
                        'strength': result.strength.name,
                        'error': result.error
                    }
                    for result in results
                ]
            }

            with self.config.export_file.open('w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to export results: {e}")

def validate_file(file_path: str) -> Optional[Path]:
    """Validate that the file exists and is readable."""
    path = Path(file_path)
    try:
        if not path.is_file():
            logger.error(f"File not found: {file_path}")
            return None
        
        path.open('r').close()
        return path
    except PermissionError:
        logger.error(f"Permission denied: {file_path}")
        return None
    except Exception as e:
        logger.error(f"Error validating file: {e}")
        return None

def read_passwords(file_path: Path) -> List[str]:
    """Read passwords from a file, skipping empty lines and stripping whitespace."""
    try:
        with file_path.open('r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Error reading passwords: {e}")
        return []

def get_strength_color(strength: PasswordStrength) -> str:
    """Get color for password strength."""
    colors = {
        PasswordStrength.VERY_WEAK: Fore.RED,
        PasswordStrength.WEAK: Fore.YELLOW,
        PasswordStrength.MEDIUM: Fore.BLUE,
        PasswordStrength.STRONG: Fore.GREEN,
        PasswordStrength.VERY_STRONG: Fore.CYAN
    }
    return colors.get(strength, Fore.WHITE)

async def main():
    """Main entry point for the password auditor."""
    parser = argparse.ArgumentParser(description="Check passwords against Have I Been Pwned API")
    parser.add_argument("file", help="Path to the password file")
    parser.add_argument("--batch-size", type=int, default=10, help="Number of concurrent requests")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--rate-limit", type=float, default=0.1, help="Delay between requests in seconds")
    parser.add_argument("--cache-file", help="File to cache results")
    parser.add_argument("--export-file", help="File to export results")
    parser.add_argument("--min-strength", type=int, choices=range(5), default=2,
                       help="Minimum password strength (0-4)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show progress bar")
    args = parser.parse_args()

    # Validate input file
    file_path = validate_file(args.file)
    if not file_path:
        sys.exit(1)

    # Create configuration
    config = Config(
        input_file=file_path,
        batch_size=args.batch_size,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        verbose=args.verbose,
        cache_file=Path(args.cache_file) if args.cache_file else None,
        export_file=Path(args.export_file) if args.export_file else None,
        min_strength=PasswordStrength(args.min_strength)
    )

    # Read passwords
    passwords = read_passwords(config.input_file)
    if not passwords:
        logger.error("No passwords found in file")
        sys.exit(1)

    # Check passwords
    auditor = PasswordAuditor(config)
    results = await auditor.check_passwords(passwords)

    # Print results
    weak_passwords = 0
    leaked_passwords = 0
    total_passwords = len(results)

    print("\nPassword Check Results:")
    print("=" * 50)

    for result in results:
        strength_color = get_strength_color(result.strength)
        
        if result.error:
            print(f"{Fore.RED}Error checking password: {result.password}")
            print(f"Error details: {result.error}{Style.RESET_ALL}")
            continue

        if result.strength.value < config.min_strength.value:
            weak_passwords += 1
            print(f"{strength_color}⚠️  WEAK: '{result.password}' - Strength: {result.strength.name}{Style.RESET_ALL}")

        if result.leak_count > 0:
            leaked_passwords += 1
            print(f"{Fore.RED}⚠️  LEAKED: '{result.password}' was found {result.leak_count} times!{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✅ '{result.password}' was not found in any known data breaches{Style.RESET_ALL}")

    # Print summary
    print("\nSummary:")
    print("=" * 50)
    print(f"Total passwords checked: {total_passwords}")
    print(f"Weak passwords: {weak_passwords}")
    print(f"Leaked passwords: {leaked_passwords}")
    print(f"Strong passwords: {total_passwords - weak_passwords}")

    # Save cache and export results
    auditor._save_cache()
    auditor.export_results(results)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
