import hashlib
import json
import math
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse


def normalize_host(value: str) -> Optional[str]:
    candidate = (value or "").strip().lower()
    if not candidate:
        return None

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    host = (parsed.hostname or "").strip(".").lower()
    if not host:
        return None

    if host.startswith("www."):
        host = host[4:]

    return host


class BloomFilter:
    def __init__(self, bit_count: int, hash_count: int) -> None:
        self.bit_count = max(1024, int(bit_count))
        self.hash_count = max(3, int(hash_count))
        self.bits = bytearray((self.bit_count + 7) // 8)

    def _positions(self, item: str):
        payload = item.encode("utf-8", errors="ignore")
        for seed in range(self.hash_count):
            digest = hashlib.blake2b(payload, digest_size=8, person=f"rbi{seed}".encode("utf-8")).digest()
            value = int.from_bytes(digest, byteorder="big", signed=False)
            yield value % self.bit_count

    def add(self, item: str) -> None:
        for bit_index in self._positions(item):
            self.bits[bit_index // 8] |= 1 << (bit_index % 8)

    def might_contain(self, item: str) -> bool:
        for bit_index in self._positions(item):
            if not (self.bits[bit_index // 8] & (1 << (bit_index % 8))):
                return False
        return True


@dataclass
class SafeLookupResult:
    matched: bool
    source: str
    host: str


class SafeUrlIndex:
    def __init__(self, source_file: str, bloom_file: str, meta_file: str) -> None:
        self.source_file = source_file
        self.bloom_file = bloom_file
        self.meta_file = meta_file
        self.filter: Optional[BloomFilter] = None
        self.entry_count = 0
        self.ready = False

    @staticmethod
    def _optimal_params(n: int, false_positive_rate: float = 0.001):
        n = max(1, n)
        m = int(-(n * math.log(false_positive_rate)) / (math.log(2) ** 2))
        k = int((m / n) * math.log(2))
        return max(8192, m), max(4, k)

    def _count_source_lines(self) -> int:
        count = 0
        with open(self.source_file, "r", encoding="utf-8", errors="ignore") as fp:
            for raw in fp:
                if normalize_host(raw):
                    count += 1
        return count

    def _build_filter(self) -> None:
        n = self._count_source_lines()
        bit_count, hash_count = self._optimal_params(n)
        bloom = BloomFilter(bit_count=bit_count, hash_count=hash_count)

        with open(self.source_file, "r", encoding="utf-8", errors="ignore") as fp:
            for raw in fp:
                host = normalize_host(raw)
                if not host:
                    continue
                bloom.add(host)

        self.filter = bloom
        self.entry_count = n

        os.makedirs(os.path.dirname(self.bloom_file), exist_ok=True)
        with open(self.bloom_file, "wb") as fp:
            fp.write(bloom.bits)

        meta = {
            "entry_count": n,
            "bit_count": bloom.bit_count,
            "hash_count": bloom.hash_count,
            "source_file": os.path.abspath(self.source_file),
            "source_mtime": os.path.getmtime(self.source_file),
        }
        with open(self.meta_file, "w", encoding="utf-8") as fp:
            json.dump(meta, fp)

    def _load_cached_filter(self) -> bool:
        if not os.path.exists(self.bloom_file) or not os.path.exists(self.meta_file):
            return False
        if not os.path.exists(self.source_file):
            return False

        with open(self.meta_file, "r", encoding="utf-8") as fp:
            meta = json.load(fp)

        expected_source = os.path.abspath(self.source_file)
        if os.path.abspath(meta.get("source_file", "")) != expected_source:
            return False

        source_mtime = os.path.getmtime(self.source_file)
        if float(meta.get("source_mtime", -1)) != float(source_mtime):
            return False

        bit_count = int(meta.get("bit_count", 0))
        hash_count = int(meta.get("hash_count", 0))
        if bit_count <= 0 or hash_count <= 0:
            return False

        bloom = BloomFilter(bit_count=bit_count, hash_count=hash_count)
        with open(self.bloom_file, "rb") as fp:
            blob = fp.read()

        if len(blob) != len(bloom.bits):
            return False

        bloom.bits[:] = blob
        self.filter = bloom
        self.entry_count = int(meta.get("entry_count", 0))
        return True

    def load(self) -> None:
        if not os.path.exists(self.source_file):
            self.ready = False
            self.filter = None
            self.entry_count = 0
            return

        if self._load_cached_filter():
            self.ready = True
            return

        self._build_filter()
        self.ready = self.filter is not None

    @lru_cache(maxsize=4096)
    def might_be_safe(self, url_or_host: str) -> SafeLookupResult:
        host = normalize_host(url_or_host) or ""
        if not host or not self.ready or not self.filter:
            return SafeLookupResult(matched=False, source="none", host=host)

        matched = self.filter.might_contain(host)
        if matched:
            return SafeLookupResult(matched=True, source="bloom", host=host)
        return SafeLookupResult(matched=False, source="bloom", host=host)


def build_default_safe_index(base_dir: str) -> SafeUrlIndex:
    source_file = os.environ.get("SAFE_URL_SOURCE_FILE", os.path.join(base_dir, "intel", "safe_domains_10m.txt"))
    bloom_file = os.environ.get("SAFE_URL_BLOOM_FILE", os.path.join(base_dir, "intel", "safe_domains_10m.bloom"))
    meta_file = os.environ.get("SAFE_URL_META_FILE", os.path.join(base_dir, "intel", "safe_domains_10m.meta.json"))
    index = SafeUrlIndex(source_file=source_file, bloom_file=bloom_file, meta_file=meta_file)
    index.load()
    return index
