import json
import os
from datetime import datetime
from threading import Lock


class EventManager:

    def __init__(self):

        self.log_directory = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "logs"
        )

        self.log_file = os.path.join(
            self.log_directory,
            "events.json"
        )

        self.lock = Lock()

        os.makedirs(
            self.log_directory,
            exist_ok=True
        )

        self._initialize_log()


    # =====================================================
    # INITIALIZE EVENT FILE
    # =====================================================

    def _initialize_log(self):

        if not os.path.exists(self.log_file):

            with open(
                self.log_file,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    [],
                    file,
                    indent=4
                )


    # =====================================================
    # ADD EVENT
    # =====================================================

    def add_event(
        self,
        event_type,
        file_path=None,
        severity="INFO",
        message="",
        risk_score=0,
        honeypot_triggered=False
    ):

        event = {

            "event_id": self._generate_event_id(),

            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            ),

            "event_type": event_type,

            "file_path": file_path,

            "severity": severity,

            "message": message,

            "risk_score": risk_score,

            "honeypot_triggered": honeypot_triggered
        }


        with self.lock:

            events = self._load_events()

            events.append(event)

            self._save_events(events)


        return event


    # =====================================================
    # GET EVENTS
    # =====================================================

    def get_events(
        self,
        limit=100
    ):

        with self.lock:

            events = self._load_events()


        # Most recent events first

        events.reverse()

        return events[:limit]


    # =====================================================
    # GET LATEST EVENT
    # =====================================================

    def get_latest_event(self):

        events = self.get_events(
            limit=1
        )

        if events:

            return events[0]

        return None


    # =====================================================
    # CLEAR EVENTS
    # =====================================================

    def clear_events(self):

        with self.lock:

            self._save_events([])


    # =====================================================
    # LOAD EVENTS
    # =====================================================

    def _load_events(self):

        try:

            with open(
                self.log_file,
                "r",
                encoding="utf-8"
            ) as file:

                return json.load(file)

        except (
            json.JSONDecodeError,
            FileNotFoundError
        ):

            return []


    # =====================================================
    # SAVE EVENTS
    # =====================================================

    def _save_events(
        self,
        events
    ):

        with open(
            self.log_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                events,
                file,
                indent=4
            )


    # =====================================================
    # EVENT ID
    # =====================================================

    def _generate_event_id(self):

        events = self._load_events()

        return f"EVT-{len(events) + 1:06d}"