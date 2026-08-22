import json
import os
from datetime import datetime
from threading import Lock


class IncidentManager:

    def __init__(self):

        self.log_directory = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "logs"
        )

        self.incident_file = os.path.join(
            self.log_directory,
            "incidents.json"
        )

        self.lock = Lock()

        os.makedirs(
            self.log_directory,
            exist_ok=True
        )

        self._initialize()


    # =====================================================
    # INITIALIZE
    # =====================================================

    def _initialize(self):

        if not os.path.exists(self.incident_file):

            with open(
                self.incident_file,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump([], file, indent=4)


    # =====================================================
    # CREATE INCIDENT
    # =====================================================

    def create_incident(
        self,
        risk_score,
        events,
        reason="Suspicious ransomware behavior detected"
    ):

        severity = self._calculate_severity(
            risk_score
        )

        incident = {

            "incident_id": self._generate_incident_id(),

            "created_at": datetime.now().isoformat(
                timespec="seconds"
            ),

            "severity": severity,

            "risk_score": risk_score,

            "status": "OPEN",

            "reason": reason,

            "event_count": len(events),

            "honeypot_triggered": any(
                event.get(
                    "honeypot_triggered",
                    False
                )
                for event in events
            ),

            "events": events
        }


        with self.lock:

            incidents = self._load_incidents()

            incidents.append(incident)

            self._save_incidents(
                incidents
            )


        return incident


    # =====================================================
    # SEVERITY
    # =====================================================

    def _calculate_severity(
        self,
        risk_score
    ):

        if risk_score >= 80:
            return "CRITICAL"

        if risk_score >= 60:
            return "HIGH"

        if risk_score >= 40:
            return "SUSPICIOUS"

        if risk_score >= 20:
            return "LOW"

        return "INFO"


    # =====================================================
    # GET INCIDENTS
    # =====================================================

    def get_incidents(
        self,
        limit=50
    ):

        with self.lock:

            incidents = self._load_incidents()

        incidents.reverse()

        return incidents[:limit]


    # =====================================================
    # GET ONE INCIDENT
    # =====================================================

    def get_incident(
        self,
        incident_id
    ):

        incidents = self._load_incidents()

        for incident in incidents:

            if incident["incident_id"] == incident_id:

                return incident

        return None


    # =====================================================
    # CLEAR INCIDENTS (used by /reset for a fresh demo run)
    # =====================================================

    def clear_incidents(self):

        with self.lock:

            self._save_incidents([])



    # =====================================================
    # UPDATE STATUS
    # =====================================================

    def update_status(
        self,
        incident_id,
        status
    ):

        allowed_statuses = [
            "OPEN",
            "INVESTIGATING",
            "CONTAINED",
            "RECOVERED",
            "CLOSED"
        ]

        if status not in allowed_statuses:

            raise ValueError(
                "Invalid incident status"
            )


        with self.lock:

            incidents = self._load_incidents()

            for incident in incidents:

                if incident["incident_id"] == incident_id:

                    incident["status"] = status

                    incident["updated_at"] = (
                        datetime.now().isoformat(
                            timespec="seconds"
                        )
                    )

                    self._save_incidents(
                        incidents
                    )

                    return incident

        return None


    # =====================================================
    # LOAD
    # =====================================================

    def _load_incidents(self):

        try:

            with open(
                self.incident_file,
                "r",
                encoding="utf-8"
            ) as file:

                return json.load(file)

        except (
            FileNotFoundError,
            json.JSONDecodeError
        ):

            return []


    # =====================================================
    # SAVE
    # =====================================================

    def _save_incidents(
        self,
        incidents
    ):

        with open(
            self.incident_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                incidents,
                file,
                indent=4
            )


    # =====================================================
    # INCIDENT ID
    # =====================================================

    def _generate_incident_id(self):

        incidents = self._load_incidents()

        return f"INC-{len(incidents) + 1:06d}"