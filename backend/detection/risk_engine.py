from collections import deque
from time import time
from pathlib import Path


class RiskEngine:

    def __init__(self):

        # Store recent filesystem events
        self.events = deque()

        # Current risk score
        self.risk_score = 0

        # Whether a honeypot has been triggered
        self.honeypot_triggered = False

        # Location of our controlled honeypots
        self.honeypot_directory = (
            Path("sandbox") / "honeypots"
        )


    # --------------------------------------------------
    # ADD FILESYSTEM EVENT
    # --------------------------------------------------

    def add_event(self, event_type, file_path):

        # Check whether this event involves a honeypot
        self.check_honeypot(file_path)

        current_time = time()

        event = {
            "type": event_type,
            "path": file_path,
            "time": current_time
        }

        self.events.append(event)

        # Remove events older than 10 seconds
        self.cleanup_old_events()

        # Recalculate risk
        self.calculate_risk()


    # --------------------------------------------------
    # HONEYPOT DETECTION
    # --------------------------------------------------

    def check_honeypot(self, file_path):

        try:

            file_path_obj = Path(file_path).resolve()

            honeypot_path = (
                self.honeypot_directory.resolve()
            )

            # Check whether the file is inside honeypots
            if honeypot_path in file_path_obj.parents:

                if not self.honeypot_triggered:

                    print()
                    print("=" * 45)
                    print("🚨 HONEYPOT TRIGGERED!")
                    print("=" * 45)

                    print(
                        f"Suspicious file: {file_path}"
                    )

                    print(
                        "Possible ransomware activity detected."
                    )

                    print("=" * 45)
                    print()

                self.honeypot_triggered = True

                return True

        except Exception as error:

            print(
                f"[HONEYPOT CHECK ERROR] {error}"
            )

        return False


    # --------------------------------------------------
    # REMOVE OLD EVENTS
    # --------------------------------------------------

    def cleanup_old_events(self):

        current_time = time()

        while self.events:

            oldest_event = self.events[0]

            if (
                current_time
                - oldest_event["time"]
                > 10
            ):

                self.events.popleft()

            else:

                break


    # --------------------------------------------------
    # CALCULATE RISK
    # --------------------------------------------------

    def calculate_risk(self):

        score = 0

        recent_events = list(self.events)


        # ----------------------------------------------
        # MODIFICATION DETECTION
        # ----------------------------------------------

        modifications = sum(
            1
            for event in recent_events
            if event["type"] == "modified"
        )


        if modifications >= 5:

            score += 20


        if modifications >= 15:

            score += 25


        if modifications >= 30:

            score += 30


        # ----------------------------------------------
        # RENAME DETECTION
        # ----------------------------------------------

        renames = sum(
            1
            for event in recent_events
            if event["type"] == "renamed"
        )


        if renames >= 5:

            score += 20


        if renames >= 15:

            score += 25


        # ----------------------------------------------
        # DELETE DETECTION
        # ----------------------------------------------

        deletions = sum(
            1
            for event in recent_events
            if event["type"] == "deleted"
        )


        if deletions >= 5:

            score += 15


        if deletions >= 15:

            score += 25


        # ----------------------------------------------
        # HONEYPOT DETECTION
        # ----------------------------------------------

        if self.honeypot_triggered:

            score += 40


        # ----------------------------------------------
        # LIMIT SCORE
        # ----------------------------------------------

        self.risk_score = min(score, 100)


    # --------------------------------------------------
    # GET SECURITY STATUS
    # --------------------------------------------------

    def get_status(self):

        if self.risk_score >= 80:

            return "CRITICAL"

        elif self.risk_score >= 60:

            return "HIGH"

        elif self.risk_score >= 30:

            return "SUSPICIOUS"

        else:

            return "NORMAL"


    # --------------------------------------------------
    # GET COMPLETE RESULT
    # --------------------------------------------------

    def get_result(self):

        return {

            "risk_score":
                self.risk_score,

            "status":
                self.get_status(),

            "events_last_10_seconds":
                len(self.events),

            "honeypot_triggered":
                self.honeypot_triggered,

            "modifications":
                sum(
                    1
                    for event in self.events
                    if event["type"] == "modified"
                ),

            "renames":
                sum(
                    1
                    for event in self.events
                    if event["type"] == "renamed"
                ),

            "deletions":
                sum(
                    1
                    for event in self.events
                    if event["type"] == "deleted"
                )
        }