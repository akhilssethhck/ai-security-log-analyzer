import os
import threading
import uuid

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
)

from parsers.manager import ParserManager
from detection_engine import run_detections
from incident.engine import IncidentEngine
from threat_intelligence.enricher import ThreatIntelligenceEnricher

from ai.soc_agent import AISOCAnalyst
from ai.model_manager import AIModelManager

from realtime.web import create_realtime_routes


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)

BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        ".."
    )
)

UPLOAD_DIR = os.path.join(
    BASE_DIR,
    "reports",
    "uploads"
)

os.makedirs(
    UPLOAD_DIR,
    exist_ok=True
)

app.config["MAX_CONTENT_LENGTH"] = (
    50 * 1024 * 1024
)


# ============================================================
# JOB STORAGE
# ============================================================

jobs = {}

jobs_lock = threading.Lock()


# ============================================================
# COMPLETE LOG ANALYSIS
# ============================================================

def analyze_log_file(
    file_path,
    model=None
):
    """
    Complete security analysis pipeline.

    Supported:
    - .log
    - .txt
    - .json
    - .csv

    Pipeline:

    File
      ↓
    Parser
      ↓
    Security Events
      ↓
    Detection Engine
      ↓
    Incident Engine
      ↓
    Threat Intelligence
      ↓
    AI SOC Analyst
    """

    parser_manager = ParserManager()

    incident_engine = IncidentEngine()

    threat_intelligence = (
        ThreatIntelligenceEnricher()
    )

    ai_analyst = AISOCAnalyst(
        model=model
    )

    # --------------------------------------------------------
    # PARSE
    # --------------------------------------------------------

    detected_type, events = (
        parser_manager.parse_file(
            file_path
        )
    )

    # --------------------------------------------------------
    # DETECTIONS
    # --------------------------------------------------------

    detections = run_detections(
        events
    )

    # --------------------------------------------------------
    # INCIDENTS
    # --------------------------------------------------------

    incidents = (
        incident_engine.create_incidents(
            detections
        )
    )

    # --------------------------------------------------------
    # THREAT INTELLIGENCE
    # --------------------------------------------------------

    for incident in incidents:

        source_ip = incident.get(
            "source_ip"
        )

        if not source_ip:
            continue

        try:

            ti_result = (
                threat_intelligence.enrich_ip(
                    source_ip
                )
            )

        except Exception as error:

            ti_result = {
                "ip": source_ip,
                "valid": True,
                "classification": "UNKNOWN",
                "reputation": "UNKNOWN",
                "malicious": None,
                "confidence": 0,
                "provider": "ERROR",
                "error": str(error),
            }

        incident[
            "threat_intelligence"
        ] = ti_result

    # --------------------------------------------------------
    # AI SOC ANALYST
    # --------------------------------------------------------

    ai_results = []

    for incident in incidents:

        try:

            result = (
                ai_analyst.analyze_incident(
                    incident
                )
            )

        except Exception as error:

            result = {
                "success": False,
                "skipped": False,
                "analyst": "AI SOC Analyst",
                "provider": "Unavailable",
                "model": (
                    model or
                    "Unavailable"
                ),
                "source_ip": incident.get(
                    "source_ip",
                    "Unknown"
                ),
                "severity": incident.get(
                    "severity",
                    "INFO"
                ),
                "risk_score": incident.get(
                    "risk_score",
                    0
                ),
                "analysis": (
                    "[AI UNAVAILABLE]\n"
                    f"Reason: {error}"
                ),
                "error": str(error),
            }

        ai_results.append(
            result
        )

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    unique_ips = set()

    usernames = set()

    event_types = set()

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for event in events:

        if event.source_ip:

            unique_ips.add(
                event.source_ip
            )

        if event.username:

            usernames.add(
                event.username
            )

        if event.event_type:

            event_types.add(
                event.event_type
            )

        severity = (
            event.severity or "INFO"
        ).upper()

        if severity in severity_counts:

            severity_counts[
                severity
            ] += 1

    return {

        "detected_type":
            detected_type,

        "events": [
            event.to_dict()
            for event in events
        ],

        "detections":
            detections,

        "incidents":
            incidents,

        "ai_analysis":
            ai_results,

        "statistics": {

            "total_events":
                len(events),

            "total_detections":
                len(detections),

            "total_incidents":
                len(incidents),

            "unique_ips":
                len(unique_ips),

            "unique_usernames":
                len(usernames),

            "event_types":
                sorted(event_types),

            "severity_counts":
                severity_counts,
        },
    }


# ============================================================
# BACKGROUND ANALYSIS JOB
# ============================================================

def run_analysis_job(
    job_id,
    file_path,
    model=None
):

    try:

        with jobs_lock:

            jobs[job_id][
                "status"
            ] = "parsing"

            jobs[job_id][
                "progress"
            ] = 10

            jobs[job_id][
                "message"
            ] = "Parsing security file..."

        # ----------------------------------------------------
        # ANALYSIS
        # ----------------------------------------------------

        with jobs_lock:

            jobs[job_id][
                "status"
            ] = "analyzing"

            jobs[job_id][
                "progress"
            ] = 35

            jobs[job_id][
                "message"
            ] = "Running security analysis..."

        result = analyze_log_file(
            file_path,
            model=model
        )

        # ----------------------------------------------------
        # COMPLETE
        # ----------------------------------------------------

        with jobs_lock:

            jobs[job_id][
                "status"
            ] = "complete"

            jobs[job_id][
                "progress"
            ] = 100

            jobs[job_id][
                "message"
            ] = "Analysis complete."

            jobs[job_id][
                "result"
            ] = result

    except Exception as error:

        with jobs_lock:

            jobs[job_id][
                "status"
            ] = "failed"

            jobs[job_id][
                "progress"
            ] = 0

            jobs[job_id][
                "message"
            ] = "Analysis failed."

            jobs[job_id][
                "error"
            ] = str(error)

    finally:

        try:

            if os.path.isfile(
                file_path
            ):

                os.remove(
                    file_path
                )

        except OSError:

            pass


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/health",
    methods=["GET"]
)
def health():

    model_manager = (
        AIModelManager()
    )

    return jsonify({

        "status":
            "online",

        "ai_available":
            model_manager.is_available(),

        "models":
            model_manager.get_models(),
    })


# ============================================================
# AI MODEL LIST
# ============================================================

@app.route(
    "/models",
    methods=["GET"]
)
def models():

    manager = (
        AIModelManager()
    )

    available = (
        manager.get_models()
    )

    default_model = (
        manager.get_default_model()
    )

    return jsonify({

        "available":
            available,

        "default":
            default_model,

        # Compatibility with the
        # current frontend.
        "models":
            available,
    })


# ============================================================
# START LOG ANALYSIS
# ============================================================

@app.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    # --------------------------------------------------------
    # FILE
    # --------------------------------------------------------

    if "log_file" not in request.files:

        return jsonify({

            "success":
                False,

            "error":
                "No security file uploaded.",
        }), 400

    uploaded_file = (
        request.files[
            "log_file"
        ]
    )

    if not uploaded_file.filename:

        return jsonify({

            "success":
                False,

            "error":
                "No filename provided.",
        }), 400

    # --------------------------------------------------------
    # EXTENSION
    # --------------------------------------------------------

    safe_filename = os.path.basename(
        uploaded_file.filename
    )

    extension = os.path.splitext(
        safe_filename
    )[1].lower()

    allowed_extensions = {
        ".log",
        ".txt",
        ".json",
        ".csv",
    }

    if extension not in allowed_extensions:

        return jsonify({

            "success":
                False,

            "error":
                (
                    "Unsupported file type. "
                    "Use .log, .txt, .json or .csv."
                ),
        }), 400

    # --------------------------------------------------------
    # SAVE UPLOAD
    # --------------------------------------------------------

    unique_filename = (
        f"{uuid.uuid4().hex}_"
        f"{safe_filename}"
    )

    file_path = os.path.join(
        UPLOAD_DIR,
        unique_filename
    )

    uploaded_file.save(
        file_path
    )

    # --------------------------------------------------------
    # MODEL
    # --------------------------------------------------------

    model = request.form.get(
        "model"
    )

    # Support old frontend
    # field as fallback.
    if not model:

        model = request.form.get(
            "ai_model"
        )

    # --------------------------------------------------------
    # CREATE JOB
    # --------------------------------------------------------

    job_id = uuid.uuid4().hex

    with jobs_lock:

        jobs[job_id] = {

            "job_id":
                job_id,

            "status":
                "queued",

            "progress":
                0,

            "message":
                "Analysis queued.",

            "result":
                None,

            "error":
                None,
        }

    # --------------------------------------------------------
    # BACKGROUND THREAD
    # --------------------------------------------------------

    worker = threading.Thread(

        target=run_analysis_job,

        args=(
            job_id,
            file_path,
            model,
        ),

        daemon=True,
    )

    worker.start()

    return jsonify({

        "success":
            True,

        "job_id":
            job_id,
    })


# ============================================================
# JOB STATUS
# ============================================================

@app.route(
    "/status/<job_id>",
    methods=["GET"]
)
def job_status(
    job_id
):

    with jobs_lock:

        job = jobs.get(
            job_id
        )

        if job is None:

            return jsonify({

                "success":
                    False,

                "error":
                    "Job not found.",
            }), 404

        return jsonify({

            "success":
                True,

            "job_id":
                job_id,

            "status":
                job["status"],

            "progress":
                job["progress"],

            "message":
                job["message"],

            "error":
                job["error"],
        })


# ============================================================
# GET ANALYSIS RESULTS
# ============================================================

@app.route(
    "/results/<job_id>",
    methods=["GET"]
)
def results(
    job_id
):

    with jobs_lock:

        job = jobs.get(
            job_id
        )

        if job is None:

            return jsonify({

                "success":
                    False,

                "error":
                    "Job not found.",
            }), 404

        if job[
            "status"
        ] != "complete":

            return jsonify({

                "success":
                    False,

                "status":
                    job["status"],

                "message":
                    job["message"],
            }), 202

        return jsonify({

            "success":
                True,

            "job_id":
                job_id,

            "result":
                job["result"],
        })


# ============================================================
# AI-ONLY ANALYSIS
# ============================================================

@app.route(
    "/ai/analyze",
    methods=["POST"]
)
def ai_analyze():

    data = request.get_json(
        silent=True
    ) or {}

    incidents = data.get(
        "incidents",
        []
    )

    model = data.get(
        "model"
    )

    if not isinstance(
        incidents,
        list
    ):

        return jsonify({

            "success":
                False,

            "error":
                "Invalid incidents data.",
        }), 400

    if not incidents:

        return jsonify({

            "success":
                True,

            "ai_analysis":
                [],

            "message":
                (
                    "No incidents available "
                    "for AI analysis."
                ),
        })

    try:

        ai_analyst = AISOCAnalyst(
            model=model
        )

        ai_results = []

        for incident in incidents:

            if not isinstance(
                incident,
                dict
            ):
                continue

            result = (
                ai_analyst.analyze_incident(
                    incident
                )
            )

            ai_results.append(
                result
            )

        return jsonify({

            "success":
                True,

            "model":
                ai_analyst.model,

            "ai_analysis":
                ai_results,
        })

    except Exception as error:

        return jsonify({

            "success":
                False,

            "error":
                str(error),
        }), 500


# ============================================================
# REAL-TIME MONITORING
# ============================================================

try:

    create_realtime_routes(
        app
    )

except Exception as error:

    print(
        "Realtime routes unavailable:",
        error
    )


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    host = os.getenv(
        "FLASK_HOST",
        "127.0.0.1"
    )

    port = int(
        os.getenv(
            "FLASK_PORT",
            "5000"
        )
    )

    print()
    print(
        "=========================================="
    )
    print(
        " AI SECURITY LOG ANALYZER"
    )
    print(
        "=========================================="
    )
    print(
        f" Server: http://{host}:{port}"
    )
    print(
        " Supported: .log .txt .json .csv"
    )
    print(
        " AI: Ollama Local SOC Analyst"
    )
    print(
        "=========================================="
    )
    print()

    app.run(
        host=host,
        port=port,
        debug=False,
        threaded=True
    )
