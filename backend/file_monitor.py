from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from backend.detection.behavior_engine import BehaviorEngine
from backend.security_state import security_state
from backend.event_manager import EventManager
from backend.incident_manager import IncidentManager
from backend.config import SANDBOX_DIR, HONEYPOT_DIR


class RansomShieldMonitor(FileSystemEventHandler):

    def __init__(self, event_manager=None, incident_manager=None):

        super().__init__()

        self.behavior_engine = BehaviorEngine()

        self.event_manager = event_manager or EventManager()
        self.incident_manager = incident_manager or IncidentManager()

        # Track files that are known honeypots
        self.honeypot_directory = HONEYPOT_DIR.resolve()

        # Debounce: only open a new incident when we cross INTO
        # HIGH/CRITICAL, not on every single event while we stay there.
        self._last_incident_status = "NORMAL"


    # ==================================================
    # CHECK HONEYPOT
    # ==================================================

    def is_honeypot(self, file_path):

        try:

            path = Path(file_path).resolve()

            return (
                self.honeypot_directory
                in path.parents
            )

        except Exception:

            return False


    # ==================================================
    # PROCESS EVENT
    # ==================================================

    def process_event(
        self,
        event_type,
        file_path
    ):

        # ----------------------------------------------
        # Check honeypot
        # ----------------------------------------------

        honeypot_triggered = self.is_honeypot(
            file_path
        )


        # ----------------------------------------------
        # Send event to Behavior Engine
        # ----------------------------------------------

        self.behavior_engine.add_event(
            event_type,
            file_path
        )


        # ----------------------------------------------
        # Analyze behavior
        # ----------------------------------------------

        result = self.behavior_engine.analyze(
            honeypot_triggered=
                honeypot_triggered
        )


        # ----------------------------------------------
        # Update shared security state
        # ----------------------------------------------

        security_state.update(

            result["risk_score"],

            result["status"],

            event_type,

            file_path,

            honeypot_triggered,

            indicators=result
        )


        # ----------------------------------------------
        # Persist to the event log (drives /events)
        # ----------------------------------------------

        severity = result["status"]

        message = (
            f"{event_type.upper()} detected on "
            f"{Path(file_path).name}"
        )

        if honeypot_triggered:
            message = (
                f"Honeypot file touched: "
                f"{Path(file_path).name}"
            )

        logged_event = self.event_manager.add_event(
            event_type=event_type,
            file_path=str(file_path),
            severity=severity,
            message=message,
            risk_score=result["risk_score"],
            honeypot_triggered=honeypot_triggered
        )


        # ----------------------------------------------
        # Open an incident when risk escalates
        # (drives /incidents)
        # ----------------------------------------------

        escalated = (
            result["status"] in ("HIGH", "CRITICAL")
            and self._last_incident_status not in ("HIGH", "CRITICAL")
        )

        if escalated or honeypot_triggered:

            reason = (
                "Honeypot file accessed - likely ransomware activity"
                if honeypot_triggered else
                "Ransomware-like file behavior detected "
                f"({result['modified_files']} modified, "
                f"{result['renamed_files']} renamed, "
                f"{result['deleted_files']} deleted "
                "in the last 10s)"
            )

            self.incident_manager.create_incident(
                risk_score=result["risk_score"],
                events=[logged_event],
                reason=reason
            )

        self._last_incident_status = result["status"]


        # ----------------------------------------------
        # Terminal output
        # ----------------------------------------------

        print()

        print("---------------------------------")

        print(
            f"Event       : "
            f"{event_type.upper()}"
        )

        print(
            f"File        : "
            f"{file_path}"
        )

        print(
            f"Risk Score  : "
            f"{result['risk_score']}/100"
        )

        print(
            f"Status      : "
            f"{result['status']}"
        )

        print(
            f"Unique Files: "
            f"{result['unique_files']}"
        )

        print(
            f"Modified    : "
            f"{result['modified_files']}"
        )

        print(
            f"Renamed     : "
            f"{result['renamed_files']}"
        )

        print(
            f"Deleted     : "
            f"{result['deleted_files']}"
        )

        if honeypot_triggered:

            print()

            print(
                "🚨 HONEYPOT TRIGGERED!"
            )

        print("---------------------------------")


    # ==================================================
    # CREATED
    # ==================================================

    def on_created(self, event):

        if not event.is_directory:

            self.process_event(
                "created",
                event.src_path
            )


    # ==================================================
    # MODIFIED
    # ==================================================

    def on_modified(self, event):

        if not event.is_directory:

            self.process_event(
                "modified",
                event.src_path
            )


    # ==================================================
    # DELETED
    # ==================================================

    def on_deleted(self, event):

        if not event.is_directory:

            self.process_event(
                "deleted",
                event.src_path
            )


    # ==================================================
    # RENAMED
    # ==================================================

    def on_moved(self, event):

        if not event.is_directory:

            self.process_event(
                "renamed",
                event.dest_path
            )


# ======================================================
# START MONITOR (BACKGROUND - used by the FastAPI app)
# ======================================================

def start_monitor_background(event_manager=None, incident_manager=None):
    """
    Start the watchdog Observer on a background thread and return it
    immediately, without blocking. This is what main.py calls on
    startup so the API server and the filesystem watcher run together
    in the same process.
    """

    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

    event_handler = RansomShieldMonitor(
        event_manager=event_manager,
        incident_manager=incident_manager
    )

    observer = Observer()

    observer.schedule(
        event_handler,
        str(SANDBOX_DIR),
        recursive=True
    )

    # Daemon so it never blocks process/server shutdown.
    observer.daemon = True

    observer.start()

    print(f"[RansomShield] Monitoring {SANDBOX_DIR} ...")

    return observer


# ======================================================
# START MONITOR (STANDALONE CLI - optional, for running
# the watcher by itself without the API server)
# ======================================================

def start_monitor():

    print("=================================")
    print("      RansomShield Monitor")
    print("=================================")
    print(f"Monitoring: {SANDBOX_DIR}")
    print()

    observer = start_monitor_background()

    print("Monitoring started...")
    print("Waiting for filesystem activity...")
    print()

    try:

        while True:

            input()

    except KeyboardInterrupt:

        print()
        print("Stopping RansomShield monitor...")
        observer.stop()

    observer.join()


# ======================================================
# MAIN
# ======================================================

if __name__ == "__main__":

    start_monitor()
