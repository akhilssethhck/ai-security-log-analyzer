import threading
import uuid

from realtime.security_monitor import RealtimeSecurityMonitor


_monitor = None
_monitor_lock = threading.Lock()


def get_monitor():
    global _monitor

    with _monitor_lock:
        return _monitor


def start_monitor(log_file, poll_interval=0.5):
    global _monitor

    with _monitor_lock:
        if _monitor is not None:
            return False, "A real-time monitor is already running."

        monitor = RealtimeSecurityMonitor(
            log_file=log_file,
            poll_interval=poll_interval,
        )

        monitor.start()

        _monitor = monitor

        return True, "Real-time monitoring started."


def stop_monitor():
    global _monitor

    with _monitor_lock:
        if _monitor is None:
            return False, "No real-time monitor is running."

        _monitor.stop()

        _monitor = None

        return True, "Real-time monitoring stopped."


def get_monitor_status():
    monitor = get_monitor()

    if monitor is None:
        return {
            "running": False,
            "message": "Real-time monitoring is stopped.",
        }

    stats = monitor.get_statistics()

    return {
        "running": True,
        "message": "Real-time monitoring is active.",
        "statistics": stats,
    }


def create_realtime_routes(app):
    """
    Registers the real-time monitoring API
    on the existing Flask application.
    """

    @app.route("/realtime/start", methods=["POST"])
    def realtime_start():
        from flask import jsonify, request

        data = request.get_json(silent=True) or {}

        log_file = data.get("log_file")

        if not log_file:
            return jsonify({
                "success": False,
                "error": "log_file is required.",
            }), 400

        try:
            poll_interval = float(
                data.get("poll_interval", 0.5)
            )
        except (TypeError, ValueError):
            return jsonify({
                "success": False,
                "error": "poll_interval must be a number.",
            }), 400

        if poll_interval < 0.1:
            poll_interval = 0.1

        try:
            success, message = start_monitor(
                log_file=log_file,
                poll_interval=poll_interval,
            )

        except FileNotFoundError as error:
            return jsonify({
                "success": False,
                "error": str(error),
            }), 404

        except Exception as error:
            return jsonify({
                "success": False,
                "error": str(error),
            }), 500

        return jsonify({
            "success": success,
            "message": message,
        })

    @app.route("/realtime/stop", methods=["POST"])
    def realtime_stop():
        from flask import jsonify

        success, message = stop_monitor()

        return jsonify({
            "success": success,
            "message": message,
        })

    @app.route("/realtime/status", methods=["GET"])
    def realtime_status():
        from flask import jsonify

        return jsonify(
            get_monitor_status()
        )

    @app.route("/realtime/events", methods=["GET"])
    def realtime_events():
        from flask import jsonify

        monitor = get_monitor()

        if monitor is None:
            return jsonify({
                "running": False,
                "events": [],
            })

        events = monitor.get_events()

        return jsonify({
            "running": True,
            "events": [
                event.to_dict()
                for event in events[-100:]
            ],
        })

    return app
