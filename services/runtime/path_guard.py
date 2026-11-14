"""
AegisKernel: Canonical Realpath Whitelist Enforcer
==================================================
Eliminates denylist-based string matching vulnerabilities (e.g. regex for .env or rm -rf).
Enforces POSIX canonical realpath resolution:
    target_path = Path(user_input).resolve()
    assert any(target_path.is_relative_to(allowed_dir) for allowed_dir in ALLOWED_PATHS)

Completely neutralizes:
- Directory traversal attacks (../../etc/shadow)
- Symlink spoofing (ln -s /etc/passwd ./allowed/passwd.txt)
- Shell escaping and obfuscation tricks ($IFS, hex quoting, quote concatenation)
- Null-byte injection (%00)
"""

import os
from pathlib import Path
from typing import List, Union, Optional

class PathTraversalViolation(PermissionError):
    """Raised when an untrusted path attempts to escape authorized workspace directories."""
    pass

class CanonicalPathGuard:
    """
    Validates and canonicalizes file paths against authorized directory trees.
    """
    def __init__(self, allowed_directories: List[Union[str, Path]]):
        self.allowed_bases: List[Path] = []
        for d in allowed_directories:
            p = Path(d).resolve(strict=False)
            self.allowed_bases.append(p)

    def add_allowed_directory(self, directory: Union[str, Path]):
        p = Path(directory).resolve(strict=False)
        if p not in self.allowed_bases:
            self.allowed_bases.append(p)

    def validate_and_resolve(self, untrusted_path: Union[str, Path], must_exist: bool = False) -> Path:
        """
        Resolves canonical path, resolving all symlinks, dot-dots, and relative references.
        Guarantees that canonical target is strictly relative to an authorized root.
        """
        path_str = str(untrusted_path)
        
        # 1. Null-byte injection check
        if "\x00" in path_str:
            raise PathTraversalViolation("Null-byte injection detected in path parameter.")

        # 2. Canonical resolution (resolves symlinks and ../ hops)
        try:
            canonical_path = Path(path_str).resolve(strict=must_exist)
        except (FileNotFoundError, RuntimeError) as e:
            if must_exist:
                raise
            # If path does not exist yet (e.g. file creation), resolve parent
            canonical_parent = Path(path_str).parent.resolve(strict=False)
            canonical_path = canonical_parent / Path(path_str).name

        # 3. Containment check: Is path strictly within an allowed root?
        is_safe = False
        for allowed_base in self.allowed_bases:
            try:
                # Python 3.9+ is_relative_to
                if canonical_path.is_relative_to(allowed_base):
                    is_safe = True
                    break
            except AttributeError:
                # Fallback for older python
                try:
                    canonical_path.relative_to(allowed_base)
                    is_safe = True
                    break
                except ValueError:
                    continue

        if not is_safe:
            raise PathTraversalViolation(
                f"Access Denied: Path '{canonical_path}' is outside authorized workspaces: "
                f"{[str(b) for b in self.allowed_bases]}"
            )

        return canonical_path
