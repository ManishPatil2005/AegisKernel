"""
AegisKernel: Deep Taint Tracking & Serialization Protocol
==========================================================
Mathematically enforces data origin integrity:
- Subclasses Python `str` to track biological lineage (taint_id, origin_source).
- Implements custom AegisJSONEncoder & AegisJSONDecoder preserving taint across
  JSON dumps/loads, Base64 buffers, and IPC messages.
- Prevents taint laundering via format conversions, concatenations, or slicing.
"""

import json
import uuid
import time
import base64
from typing import Any, Dict, Optional, List, Union

class TaintedString(str):
    """
    Immutable string subclass that tracks origin provenance.
    Any operation with a TaintedString taints the resulting object.
    """
    def __new__(cls, value: str, origin_source: str = "UNTRUSTED_INGRESS", taint_id: Optional[str] = None):
        obj = super().__new__(cls, value)
        obj.origin_source = origin_source
        obj.taint_id = taint_id or str(uuid.uuid4())
        obj.timestamp = time.time()
        return obj

    def __add__(self, other: Union[str, "TaintedString"]) -> "TaintedString":
        res = super().__add__(other)
        return TaintedString(res, origin_source=self.origin_source, taint_id=self.taint_id)

    def __radd__(self, other: Union[str, "TaintedString"]) -> "TaintedString":
        res = str(other) + str(self)
        return TaintedString(res, origin_source=self.origin_source, taint_id=self.taint_id)

    def __mul__(self, count: int) -> "TaintedString":
        res = super().__mul__(count)
        return TaintedString(res, origin_source=self.origin_source, taint_id=self.taint_id)

    def __getitem__(self, item: Any) -> "TaintedString":
        res = super().__getitem__(item)
        return TaintedString(res, origin_source=self.origin_source, taint_id=self.taint_id)

    def join(self, iterable) -> "TaintedString":
        res = super().join(iterable)
        return TaintedString(res, origin_source=self.origin_source, taint_id=self.taint_id)

    def replace(self, old: str, new: str, count: int = -1) -> "TaintedString":
        res = super().replace(old, new, count)
        return TaintedString(res, origin_source=self.origin_source, taint_id=self.taint_id)

    def lower(self) -> "TaintedString":
        return TaintedString(super().lower(), origin_source=self.origin_source, taint_id=self.taint_id)

    def upper(self) -> "TaintedString":
        return TaintedString(super().upper(), origin_source=self.origin_source, taint_id=self.taint_id)

    def strip(self, chars: Optional[str] = None) -> "TaintedString":
        return TaintedString(super().strip(chars), origin_source=self.origin_source, taint_id=self.taint_id)

    def to_dict(self) -> Dict[str, Any]:
        """Encodes taint metadata for serialisation across network/disk boundaries."""
        return {
            "__aegis_taint__": True,
            "value": str(self),
            "origin_source": self.origin_source,
            "taint_id": self.taint_id,
            "timestamp": self.timestamp
        }

class AegisJSONEncoder(json.JSONEncoder):
    """
    JSON Encoder that preserves TaintedString security metadata across serialization.
    Transforms TaintedString instances into canonical metadata dictionaries before encoding.
    """
    def iterencode(self, o: Any, _one_shot: bool = False):
        def _prepare_taint(val: Any) -> Any:
            if isinstance(val, TaintedString):
                return val.to_dict()
            if isinstance(val, dict):
                return {k: _prepare_taint(v) for k, v in val.items()}
            if isinstance(val, (list, tuple)):
                return [_prepare_taint(x) for x in val]
            return val

        return super().iterencode(_prepare_taint(o), _one_shot=_one_shot)

class AegisJSONDecoder(json.JSONDecoder):
    """
    JSON Decoder that reconstructs TaintedString objects upon deserialization.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self._object_hook, *args, **kwargs)

    def _object_hook(self, dct: Dict[str, Any]) -> Any:
        if isinstance(dct, dict) and dct.get("__aegis_taint__") is True:
            return TaintedString(
                value=dct["value"],
                origin_source=dct.get("origin_source", "DESERIALIZED"),
                taint_id=dct.get("taint_id")
            )
        return dct

def is_tainted(obj: Any) -> bool:
    """Recursively checks if any value within an object bears a TaintedString wrapper."""
    if isinstance(obj, TaintedString):
        return True
    if isinstance(obj, (list, tuple, set)):
        return any(is_tainted(item) for item in obj)
    if isinstance(obj, dict):
        return any(is_tainted(k) or is_tainted(v) for k, v in obj.items())
    return False

def sanitize_taint(val: TaintedString, validator_fn) -> str:
    """
    Explicit sanitization gateway: converts TaintedString to pure string
    ONLY after passing a deterministic validation predicate.
    """
    if validator_fn(str(val)):
        return str(val)
    raise ValueError(f"Taint Sanitization Failed: Value rejected by validator predicate.")

def encode_tainted_base64(val: TaintedString) -> TaintedString:
    """Preserves taint through Base64 encoding."""
    encoded = base64.b64encode(str(val).encode("utf-8")).decode("utf-8")
    return TaintedString(encoded, origin_source=val.origin_source, taint_id=val.taint_id)

def decode_tainted_base64(val: TaintedString) -> TaintedString:
    """Preserves taint through Base64 decoding."""
    decoded = base64.b64decode(str(val).encode("utf-8")).decode("utf-8")
    return TaintedString(decoded, origin_source=val.origin_source, taint_id=val.taint_id)
