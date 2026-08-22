from datetime import datetime
from threading import Lock


class SecurityState:

    def __init__(self):

        self.lock = Lock()

        self.risk_score = 0
        self.status = "NORMAL"

        self.monitoring = True

        # Track distinct files ever seen, not just event count,
        # so "files monitored" reflects real coverage instead of
        # inflating every time the same file is touched twice.
        self._monitored_files = set()
        self.threats_blocked = 0

        self.honeypot_triggered = False

        self.last_event = None
        self.last_event_time = None

        self.activity = []

        # Full behavior-engine breakdown from the most recent event
        # (modified/renamed/deleted counts, suspicious extensions, etc).
        self.indicators = {
            "events_last_10_seconds": 0,
            "unique_files": 0,
            "modified_files": 0,
            "renamed_files": 0,
            "deleted_files": 0,
            "suspicious_extensions": []
        }


    def update(
        self,
        risk_score,
        status,
        event_type,
        file_path,
        honeypot_triggered,
        indicators=None
    ):

        with self.lock:

            self.risk_score = risk_score
            self.status = status

            self.honeypot_triggered = (
                self.honeypot_triggered or honeypot_triggered
            )

            self._monitored_files.add(str(file_path))

            self.last_event = {
                "type": event_type,
                "file": str(file_path)
            }

            self.last_event_time = (
                datetime.now().isoformat()
            )

            # Store recent activity
            self.activity.insert(
                0,
                {
                    "type": event_type,
                    "file": str(file_path),
                    "time": self.last_event_time,
                    "risk_score": risk_score
                }
            )

            # Keep only latest 50 events
            self.activity = self.activity[:50]

            # Count high-risk events
            if status in ["HIGH", "CRITICAL"]:

                self.threats_blocked += 1

            if indicators is not None:

                self.indicators = {
                    "events_last_10_seconds": indicators.get(
                        "events_last_10_seconds", 0
                    ),
                    "unique_files": indicators.get("unique_files", 0),
                    "modified_files": indicators.get("modified_files", 0),
                    "renamed_files": indicators.get("renamed_files", 0),
                    "deleted_files": indicators.get("deleted_files", 0),
                    "suspicious_extensions": indicators.get(
                        "suspicious_extensions", []
                    ),
                }


    def get_state(self):

        with self.lock:

            return {

                "risk_score":
                    self.risk_score,

                "status":
                    self.status,

                "monitoring":
                    self.monitoring,

                "files_monitored":
                    len(self._monitored_files),

                "threats_blocked":
                    self.threats_blocked,

                "honeypot_triggered":
                    self.honeypot_triggered,

                "last_event":
                    self.last_event,

                "last_event_time":
                    self.last_event_time,

                "activity":
                    self.activity,

                "indicators":
                    self.indicators
            }


    def reset(self):
        """Clear counters for a fresh demo/simulation run."""

        with self.lock:

            self.risk_score = 0
            self.status = "NORMAL"
            self._monitored_files.clear()
            self.threats_blocked = 0
            self.honeypot_triggered = False
            self.last_event = None
            self.last_event_time = None
            self.activity = []
            self.indicators = {
                "events_last_10_seconds": 0,
                "unique_files": 0,
                "modified_files": 0,
                "renamed_files": 0,
                "deleted_files": 0,
                "suspicious_extensions": []
            }


# One shared state object
security_state = SecurityState()
