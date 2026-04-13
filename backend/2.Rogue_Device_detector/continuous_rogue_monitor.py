#!/usr/bin/env python3
"""
Cleaned Continuous Rogue Monitor (Option C)

- Keeps your structure but improves safety, reliability and maintainability.
- Uses the public detector API: detector.monitor_all_devices()
- Thread-safe, graceful shutdown, backoff when Module-1 unavailable,
  de-duplicates stored rogue devices, and exposes utility methods.
"""

from __future__ import annotations
import threading
import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

# Import the refactored detector
from .rogue_device_detector import RogueDeviceDetector

logger = logging.getLogger("ContinuousRogueMonitor")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")


class ContinuousRogueMonitor:
    """
    Continuous monitoring system that classifies WiFi and Bluetooth rogue devices
    separately. Keeps structure similar to your prior file but with better practices.
    """

    def __init__(self, scan_interval: int = 30, detector: Optional[RogueDeviceDetector] = None):
        """
        Args:
            scan_interval: seconds between scans
            detector: a RogueDeviceDetector instance (if None we construct one)
        """
        self.scan_interval = max(5, int(scan_interval))  # min 5s to avoid hammering
        self.detector = detector or RogueDeviceDetector()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

        # Deduplicated store: dict[device_id] -> device dict
        self.rogue_wifi_devices: Dict[str, Dict[str, Any]] = {}
        self.rogue_bluetooth_devices: Dict[str, Dict[str, Any]] = {}

        # Statistics
        self.stats = {
            "total_scans": 0,
            "total_wifi_scanned": 0,
            "total_bluetooth_scanned": 0,
            "total_rogue_wifi": 0,
            "total_rogue_bluetooth": 0,
            "last_scan_time": None,
            "last_scan_duration": 0.0,
            "consecutive_failures": 0
        }

        # Backoff control when Module-1 or Detector fails
        self._min_backoff = 5
        self._max_backoff = 300  # 5 minutes
        self._current_backoff = self.scan_interval

        logger.info("ContinuousRogueMonitor initialized (scan_interval=%ds)", self.scan_interval)

    # ---- Public lifecycle methods ----
    def start(self) -> None:
        """Start background monitoring thread (idempotent)."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                logger.warning("Monitor is already running")
                return

            self._stop_event.clear()
            self._thread = threading.Thread(target=self._monitor_loop, name="ContinuousRogueMonitorThread", daemon=True)
            self._thread.start()
            logger.info("Continuous rogue monitoring started")

    def stop(self, wait_timeout: float = 5.0) -> None:
        """Stop background monitoring and wait for thread to join."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=wait_timeout)
        # Call detector shutdown if available (to stop async DB writer)
        try:
            shutdown = getattr(self.detector, "shutdown", None)
            if callable(shutdown):
                shutdown()
        except Exception:
            logger.exception("Error during detector shutdown")
        logger.info("Continuous rogue monitoring stopped")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

    # ---- Main loop ----
    def _monitor_loop(self) -> None:
        """Main monitoring loop. Delegates analysis to the detector."""
        logger.info("Monitor loop waiting 5s for systems to become ready...")
        time.sleep(5)

        while not self._stop_event.is_set():
            scan_start = time.time()
            try:
                # Use the detector's public monitor_all_devices (no private method usage)
                result = self.detector.monitor_all_devices()

                # Basic result validation
                if not isinstance(result, dict):
                    raise RuntimeError("Detector returned unexpected result type")

                # Pull lists safely
                wifi_list = result.get("wifi_networks", []) or []
                bt_list = result.get("bluetooth_devices", []) or []
                rogue_list = result.get("rogue_devices", []) or []
                monitoring_logs = result.get("monitoring_logs", []) or []

                # Update stats
                scan_duration = time.time() - scan_start
                with self._lock:
                    self.stats["total_scans"] += 1
                    self.stats["total_wifi_scanned"] = len(wifi_list)
                    self.stats["total_bluetooth_scanned"] = len(bt_list)
                    self.stats["last_scan_time"] = datetime.utcnow().isoformat()
                    self.stats["last_scan_duration"] = round(scan_duration, 3)
                    self.stats["consecutive_failures"] = 0
                    self._current_backoff = self.scan_interval  # reset backoff on success

                # Separate and store rogue devices into dedup caches
                self._update_rogue_caches(rogue_list)

                # Logging summary
                with self._lock:
                    self.stats["total_rogue_wifi"] = len(self.rogue_wifi_devices)
                    self.stats["total_rogue_bluetooth"] = len(self.rogue_bluetooth_devices)

                logger.info("Scan #%d complete (%.2fs) — WiFi %d, BT %d, Rogue WiFi %d, Rogue BT %d",
                            self.stats["total_scans"],
                            scan_duration,
                            len(wifi_list),
                            len(bt_list),
                            self.stats["total_rogue_wifi"],
                            self.stats["total_rogue_bluetooth"])

                # Sleep regular interval
                if self._stop_event.wait(self.scan_interval):
                    break

            except Exception as e:
                # Failure/backoff handling
                logger.exception("Error during scan: %s", e)
                with self._lock:
                    self.stats["consecutive_failures"] += 1
                    # Exponential backoff with cap
                    self._current_backoff = min(self._current_backoff * 2 if self._current_backoff else self._min_backoff, self._max_backoff)
                    backoff = self._current_backoff
                logger.warning("Backing off for %ds before retry (consecutive failures: %d)", backoff, self.stats["consecutive_failures"])
                if self._stop_event.wait(backoff):
                    break

    # ---- Helper methods ----
    def _update_rogue_caches(self, rogue_devices: List[Dict[str, Any]]) -> None:
        """
        Accepts the detector's rogue_devices list (each entry should contain
        device_id, device_type, first_seen, last_seen, etc.)
        and updates internal deduplicated caches.
        """
        with self._lock:
            for dev in rogue_devices:
                # Best-effort extraction of device_id — try common keys
                device_id = dev.get("device_id") or self._make_device_id(dev)
                dtype = (dev.get("device_type") or dev.get("type") or dev.get("device_type", "")).lower()

                # Normalize timestamps
                now_ts = datetime.utcnow().isoformat()
                dev.setdefault("first_seen", now_ts)
                dev["last_seen"] = now_ts
                dev["detected_at"] = now_ts

                if dtype == "wifi":
                    # Merge if exists (keep earliest first_seen, update last_seen)
                    existing = self.rogue_wifi_devices.get(device_id)
                    if existing:
                        existing["last_seen"] = dev["last_seen"]
                        # merge threat_reasons (unique)
                        existing["threat_reasons"] = self._merge_reasons(existing.get("threat_reasons", []), dev.get("threat_reasons", []))
                        # update score/level if new is higher
                        existing_score = float(existing.get("confidence_score", 0) or 0)
                        new_score = float(dev.get("confidence_score", 0) or 0)
                        if new_score > existing_score:
                            existing.update({k: v for k, v in dev.items() if k not in ("first_seen",)})
                    else:
                        self.rogue_wifi_devices[device_id] = dev.copy()
                else:
                    # default to bluetooth bucket
                    existing = self.rogue_bluetooth_devices.get(device_id)
                    if existing:
                        existing["last_seen"] = dev["last_seen"]
                        existing["threat_reasons"] = self._merge_reasons(existing.get("threat_reasons", []), dev.get("threat_reasons", []))
                        existing_score = float(existing.get("confidence_score", 0) or 0)
                        new_score = float(dev.get("confidence_score", 0) or 0)
                        if new_score > existing_score:
                            existing.update({k: v for k, v in dev.items() if k not in ("first_seen",)})
                    else:
                        self.rogue_bluetooth_devices[device_id] = dev.copy()

    def _make_device_id(self, dev: Dict[str, Any]) -> str:
        """
        Create a stable device id fallback if detector didn't provide one.
        Prefer MAC/BSSID, otherwise hash the device dict.
        """
        mac_like = dev.get("mac_address") or dev.get("bssid") or dev.get("address") or dev.get("device_mac") or ""
        if mac_like:
            return str(mac_like).lower()
        # fallback: hash of JSON
        import hashlib, json
        return hashlib.sha256(json.dumps(dev, sort_keys=True).encode()).hexdigest()[:32]

    @staticmethod
    def _merge_reasons(a: List[str], b: List[str]) -> List[str]:
        s = list(dict.fromkeys((a or []) + (b or [])))  # preserve order, unique
        return s

    # ---- Public getters & utilities ----
    def get_status(self) -> Dict[str, Any]:
        """Thread-safe status snapshot."""
        with self._lock:
            return {
                "is_running": self.is_running(),
                "scan_interval": self.scan_interval,
                "last_scan_time": self.stats["last_scan_time"],
                "statistics": self.stats.copy(),
                "rogue_wifi_count": len(self.rogue_wifi_devices),
                "rogue_bluetooth_count": len(self.rogue_bluetooth_devices),
            }

    def get_rogue_wifi_devices(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.rogue_wifi_devices.values())

    def get_rogue_bluetooth_devices(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.rogue_bluetooth_devices.values())

    def get_all_rogue_devices(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "rogue_wifi_devices": list(self.rogue_wifi_devices.values()),
                "rogue_bluetooth_devices": list(self.rogue_bluetooth_devices.values()),
                "total_rogue_wifi": len(self.rogue_wifi_devices),
                "total_rogue_bluetooth": len(self.rogue_bluetooth_devices),
                "total_rogue_devices": len(self.rogue_wifi_devices) + len(self.rogue_bluetooth_devices),
                "last_scan": self.stats["last_scan_time"],
                "statistics": self.stats.copy()
            }

    def reset_caches(self) -> None:
        """Clear stored rogue device caches (safe to call while running)."""
        with self._lock:
            self.rogue_wifi_devices.clear()
            self.rogue_bluetooth_devices.clear()
            logger.info("Rogue caches cleared")

    def run_once(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Run a single scan/analysis synchronously and return analysis.
        Useful for on-demand checks from CLI or API.
        """
        # We call detector.monitor_all_devices() synchronously
        try:
            result = self.detector.monitor_all_devices()
            self._update_rogue_caches(result.get("rogue_devices", []))
            return result
        except Exception as e:
            logger.exception("run_once error: %s", e)
            raise

# Global helper to create a singleton-style monitor used by CLI/presentation code
_monitor_singleton: Optional[ContinuousRogueMonitor] = None


def get_continuous_monitor(scan_interval: int = 30) -> ContinuousRogueMonitor:
    global _monitor_singleton
    if _monitor_singleton is None:
        _monitor_singleton = ContinuousRogueMonitor(scan_interval=scan_interval)
    return _monitor_singleton


# If invoked directly, run a short local test similar to your previous main guard
if __name__ == "__main__":
    mon = ContinuousRogueMonitor(scan_interval=10)
    mon.start()

    try:
        for i in range(6):
            time.sleep(10)
            print(f"\nStatus (poll #{i+1}): {mon.get_status()}")
            # show up to 3 devices each
            all_rogue = mon.get_all_rogue_devices()
            if all_rogue["rogue_wifi_devices"]:
                print("Sample Rogue WiFi:")
                for d in all_rogue["rogue_wifi_devices"][:3]:
                    print(f" - {d.get('ssid')} ({d.get('bssid')}) -> {d.get('threat_level')} score:{d.get('confidence_score')}")
            if all_rogue["rogue_bluetooth_devices"]:
                print("Sample Rogue BT:")
                for d in all_rogue["rogue_bluetooth_devices"][:3]:
                    print(f" - {d.get('name')} ({d.get('mac_address')}) -> {d.get('threat_level')} score:{d.get('confidence_score')}")
    except KeyboardInterrupt:
        print("Stopping monitor...")
    finally:
        mon.stop()
        print("Monitor stopped.")
