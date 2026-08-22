import shutil
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.config import (
    ensure_directories,
    DOCUMENTS_DIR,
    HONEYPOT_DIR,
    FRONTEND_DIR,
)
from backend.security_state import security_state
from backend.event_manager import EventManager
from backend.incident_manager import IncidentManager
from backend.honeypot import create_honeypots, list_honeypots
from backend.file_monitor import start_monitor_background


app = FastAPI(
    title="RansomShield",
    description="Windows Ransomware Detection and Response Platform",
    version="1.0"
)


# --------------------------------------------------
# CORS
# --------------------------------------------------

app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)


# --------------------------------------------------
# Shared managers + monitor handle (populated on startup)
# --------------------------------------------------

event_manager = EventManager()
incident_manager = IncidentManager()

_observer = None


@app.on_event("startup")
def on_startup():

    global _observer

    ensure_directories()
    create_honeypots()

    _observer = start_monitor_background(
        event_manager=event_manager,
        incident_manager=incident_manager
    )


@app.on_event("shutdown")
def on_shutdown():

    if _observer is not None:
        _observer.stop()
        _observer.join(timeout=2)


# --------------------------------------------------
# ROOT / HEALTH
# --------------------------------------------------

@app.get("/api")
def api_root():

    return {

        "name": "RansomShield",

        "status": "online",

        "message":
            "RansomShield backend is running"
    }


@app.get("/health")
def health():

    return {

        "backend": "online",

        "monitoring":
            security_state.monitoring
    }


# --------------------------------------------------
# SECURITY STATUS
# --------------------------------------------------

@app.get("/status")
def status():

    return security_state.get_state()


# --------------------------------------------------
# ACTIVITY (kept for backwards compatibility with the
# original frontend, which reads state["activity"])
# --------------------------------------------------

@app.get("/activity")
def activity():

    state = security_state.get_state()

    return {

        "activity":
            state["activity"]
    }


# --------------------------------------------------
# EVENTS
# --------------------------------------------------

@app.get("/events")
def get_events(limit: int = 100):

    return {
        "events": event_manager.get_events(limit=limit)
    }


# --------------------------------------------------
# INCIDENTS
# --------------------------------------------------

class IncidentStatusUpdate(BaseModel):
    status: str


@app.get("/incidents")
def get_incidents(limit: int = 50):

    return {
        "incidents": incident_manager.get_incidents(limit=limit)
    }


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):

    incident = incident_manager.get_incident(incident_id)

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident


@app.post("/incidents/{incident_id}/status")
def update_incident_status(incident_id: str, body: IncidentStatusUpdate):

    try:
        incident = incident_manager.update_status(incident_id, body.status)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident


# --------------------------------------------------
# HONEYPOTS / DECEPTION CENTER
# --------------------------------------------------

@app.get("/honeypots")
def get_honeypots():

    state = security_state.get_state()

    return {
        "honeypots": list_honeypots(),
        "triggered": state["honeypot_triggered"]
    }


# --------------------------------------------------
# SIMULATION (for demoing detection without real
# ransomware - writes/renames/deletes a burst of test
# files inside sandbox/documents so the *real* watcher
# and behavior engine pick them up organically)
# --------------------------------------------------

class SimulateRequest(BaseModel):
    trigger_honeypot: bool = False


def _run_simulation(trigger_honeypot: bool):

    DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)

    created = []

    # Rapidly create + "encrypt" (rename) a batch of files - this is
    # the exact pattern the behavior engine's burst detectors look for.
    for index in range(12):

        file_path = DOCUMENTS_DIR / f"sim_file_{index}.txt"
        file_path.write_text("simulated document contents\n")
        created.append(file_path)
        time.sleep(0.05)

    for file_path in created:

        encrypted_path = file_path.with_suffix(".enc")
        file_path.rename(encrypted_path)
        time.sleep(0.05)

    for file_path in created:

        encrypted_path = file_path.with_suffix(".enc")
        if encrypted_path.exists():
            encrypted_path.unlink()
        time.sleep(0.05)

    if trigger_honeypot:

        honeypot_files = list(HONEYPOT_DIR.glob("*.txt"))

        if honeypot_files:
            target = honeypot_files[0]
            target.write_text(
                target.read_text() + "\n[simulated tampering]\n"
            )


@app.post("/simulate")
def simulate_attack(body: SimulateRequest):
    """
    Kicks off a safe, self-contained simulated attack in a background
    thread and returns immediately. Watch /status or /events right
    after calling this to see the risk score climb in real time.
    """

    thread = threading.Thread(
        target=_run_simulation,
        args=(body.trigger_honeypot,),
        daemon=True
    )
    thread.start()

    return {
        "message": "Simulation started",
        "trigger_honeypot": body.trigger_honeypot
    }


# --------------------------------------------------
# RESET (clears counters + simulated files for a fresh
# demo run - does not touch real honeypot definitions)
# --------------------------------------------------

@app.post("/reset")
def reset_state():

    security_state.reset()
    event_manager.clear_events()
    incident_manager.clear_incidents()

    for leftover in DOCUMENTS_DIR.glob("sim_file_*"):
        leftover.unlink(missing_ok=True)

    return {"message": "State reset"}


# --------------------------------------------------
# FRONTEND (served from the same origin as the API so
# there is nothing to configure - open http://127.0.0.1:8000/)
# --------------------------------------------------

if FRONTEND_DIR.exists():
    app.mount(
        "/",
        StaticFiles(directory=str(FRONTEND_DIR), html=True),
        name="frontend"
    )
