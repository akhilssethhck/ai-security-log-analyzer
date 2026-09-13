import os
import time
import threading


class LogMonitor:
    """
    Watches a log file for newly appended lines.
    Existing log entries are skipped.
    """

    def __init__(self, file_path, callback=None, poll_interval=0.5):
        self.file_path = file_path
        self.callback = callback
        self.poll_interval = poll_interval
        self.running = False
        self.thread = None

    def start(self):
        if self.running:
            return

        if not os.path.isfile(self.file_path):
            raise FileNotFoundError(
                f"Log file does not exist: {self.file_path}"
            )

        self.running = True

        self.thread = threading.Thread(
            target=self._monitor,
            daemon=True
        )

        self.thread.start()

    def stop(self):
        self.running = False

        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)

    def _monitor(self):
        try:
            with open(
                self.file_path,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as log_file:

                # Start at the end of the existing log.
                log_file.seek(0, os.SEEK_END)

                while self.running:
                    line = log_file.readline()

                    if line:
                        line = line.rstrip("\r\n")

                        if line and self.callback:
                            try:
                                self.callback(line)
                            except Exception as error:
                                print(
                                    f"[LogMonitor] Callback error: {error}"
                                )
                    else:
                        time.sleep(self.poll_interval)

        except FileNotFoundError:
            print(
                f"[LogMonitor] Log file disappeared: "
                f"{self.file_path}"
            )

        except Exception as error:
            print(
                f"[LogMonitor] Monitoring error: {error}"
            )
