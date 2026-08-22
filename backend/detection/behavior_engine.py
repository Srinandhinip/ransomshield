from collections import deque
from pathlib import Path
from time import time


class BehaviorEngine:
    """
    Analyzes filesystem activity patterns.

    This module does NOT modify, encrypt, delete, or restore files.
    It only observes events and calculates behavioral indicators.
    """

    def __init__(self, window_seconds=10):

        self.window_seconds = window_seconds

        # Recent filesystem events
        self.events = deque()

        # Unique files affected during the current window
        self.modified_files = set()
        self.created_files = set()
        self.deleted_files = set()
        self.renamed_files = set()

        # Suspicious extensions
        self.suspicious_extensions = {
            ".enc",
            ".encrypted",
            ".locked",
            ".crypt",
            ".ransom"
        }


    # ==================================================
    # ADD EVENT
    # ==================================================

    def add_event(self, event_type, file_path):

        current_time = time()

        file_path = str(
            Path(file_path).resolve()
        )

        event = {
            "time": current_time,
            "type": event_type.lower(),
            "file": file_path
        }

        self.events.append(event)

        # Track unique files
        if event_type.lower() == "modified":
            self.modified_files.add(file_path)

        elif event_type.lower() == "created":
            self.created_files.add(file_path)

        elif event_type.lower() == "deleted":
            self.deleted_files.add(file_path)

        elif event_type.lower() == "renamed":
            self.renamed_files.add(file_path)

        self._cleanup(current_time)


    # ==================================================
    # REMOVE OLD EVENTS
    # ==================================================

    def _cleanup(self, current_time):

        cutoff = (
            current_time -
            self.window_seconds
        )

        while (
            self.events
            and self.events[0]["time"] < cutoff
        ):

            self.events.popleft()


    # ==================================================
    # EVENT COUNTS
    # ==================================================

    def get_event_count(self, event_type):

        event_type = event_type.lower()

        return sum(
            1
            for event in self.events
            if event["type"] == event_type
        )


    # ==================================================
    # TOTAL EVENTS
    # ==================================================

    def get_total_events(self):

        return len(self.events)


    # ==================================================
    # UNIQUE FILE COUNT
    # ==================================================

    def get_unique_files(self):

        files = set()

        for event in self.events:
            files.add(event["file"])

        return len(files)


    # ==================================================
    # SUSPICIOUS EXTENSION
    # ==================================================

    def detect_suspicious_extensions(self):

        suspicious_files = []

        for event in self.events:

            path = Path(event["file"])

            if (
                path.suffix.lower()
                in self.suspicious_extensions
            ):

                suspicious_files.append(
                    event["file"]
                )

        return list(
            set(suspicious_files)
        )


    # ==================================================
    # MODIFICATION BURST
    # ==================================================

    def detect_modification_burst(self):

        count = len(
            self.modified_files
        )

        if count >= 50:
            return "CRITICAL"

        if count >= 20:
            return "HIGH"

        if count >= 10:
            return "MEDIUM"

        return "LOW"


    # ==================================================
    # RENAME BURST
    # ==================================================

    def detect_rename_burst(self):

        count = len(
            self.renamed_files
        )

        if count >= 20:
            return "CRITICAL"

        if count >= 10:
            return "HIGH"

        if count >= 5:
            return "MEDIUM"

        return "LOW"


    # ==================================================
    # DELETE BURST
    # ==================================================

    def detect_delete_burst(self):

        count = len(
            self.deleted_files
        )

        if count >= 20:
            return "CRITICAL"

        if count >= 10:
            return "HIGH"

        if count >= 5:
            return "MEDIUM"

        return "LOW"


    # ==================================================
    # CALCULATE BEHAVIOR SCORE
    # ==================================================

    def calculate_behavior_score(
        self,
        honeypot_triggered=False
    ):

        score = 0

        # ----------------------------------------------
        # Unique modified files
        # ----------------------------------------------

        modified_count = len(
            self.modified_files
        )

        if modified_count >= 50:
            score += 35

        elif modified_count >= 20:
            score += 25

        elif modified_count >= 10:
            score += 15

        elif modified_count >= 5:
            score += 5


        # ----------------------------------------------
        # Rename activity
        # ----------------------------------------------

        rename_count = len(
            self.renamed_files
        )

        if rename_count >= 20:
            score += 25

        elif rename_count >= 10:
            score += 15

        elif rename_count >= 5:
            score += 10


        # ----------------------------------------------
        # Delete activity
        # ----------------------------------------------

        delete_count = len(
            self.deleted_files
        )

        if delete_count >= 20:
            score += 25

        elif delete_count >= 10:
            score += 15

        elif delete_count >= 5:
            score += 10


        # ----------------------------------------------
        # Suspicious extensions
        # ----------------------------------------------

        suspicious_files = (
            self.detect_suspicious_extensions()
        )

        if len(suspicious_files) >= 10:
            score += 20

        elif len(suspicious_files) >= 3:
            score += 15

        elif len(suspicious_files) >= 1:
            score += 10


        # ----------------------------------------------
        # Honeypot
        # ----------------------------------------------

        if honeypot_triggered:
            score += 40


        # Maximum = 100
        return min(score, 100)


    # ==================================================
    # RISK LEVEL
    # ==================================================

    @staticmethod
    def get_status(score):

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 30:
            return "SUSPICIOUS"

        return "NORMAL"


    # ==================================================
    # ANALYSIS RESULT
    # ==================================================

    def analyze(
        self,
        honeypot_triggered=False
    ):

        score = self.calculate_behavior_score(
            honeypot_triggered
        )

        return {

            "risk_score": score,

            "status":
                self.get_status(score),

            "events_last_10_seconds":
                self.get_total_events(),

            "unique_files":
                self.get_unique_files(),

            "modified_files":
                len(self.modified_files),

            "renamed_files":
                len(self.renamed_files),

            "deleted_files":
                len(self.deleted_files),

            "suspicious_extensions":
                self.detect_suspicious_extensions(),

            "honeypot_triggered":
                honeypot_triggered
        }


    # ==================================================
    # RESET
    # ==================================================

    def reset(self):

        self.events.clear()

        self.modified_files.clear()

        self.created_files.clear()

        self.deleted_files.clear()

        self.renamed_files.clear()