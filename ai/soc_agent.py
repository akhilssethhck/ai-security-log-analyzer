import os

from ai.context_builder import build_incident_context
from ai.prompts import build_soc_prompt
from ai.providers.local import LocalOllamaProvider


class AISOCAnalyst:
    """
    Local AI SOC analyst using Ollama.

    Fast model:
        qwen3:1.7b

    Advanced model:
        llama3.2:latest
    """

    FAST_MODEL = "qwen3:1.7b"
    ADVANCED_MODEL = "llama3.2:latest"

    def __init__(self, model=None):
        self.model = model or os.getenv(
            "OLLAMA_MODEL",
            self.FAST_MODEL
        )

        self.provider = LocalOllamaProvider(
            model=self.model
        )

    def analyze_incident(self, incident):
        """
        Analyze one security incident.

        Only incidents with meaningful security severity
        are sent to the local LLM.
        """

        severity = str(
            incident.get("severity", "INFO")
        ).upper()

        if severity in {"INFO", "LOW"}:
            return {
                "success": True,
                "skipped": True,
                "model": self.model,
                "analysis": "AI analysis skipped for low-priority activity."
            }

        try:
            context = build_incident_context(incident)

            prompt = build_soc_prompt(context)

            result = self.provider.generate(
                prompt=prompt,
                model=self.model,
                temperature=0.1,
                max_tokens=300,
            )

            return {
                "success": True,
                "skipped": False,
                "model": result.get("model", self.model),
                "analysis": result.get("response", ""),
                "performance": {
                    "total_duration": result.get("total_duration"),
                    "load_duration": result.get("load_duration"),
                    "prompt_tokens": result.get(
                        "prompt_eval_count"
                    ),
                    "output_tokens": result.get(
                        "eval_count"
                    ),
                },
            }

        except Exception as error:
            return {
                "success": False,
                "skipped": False,
                "model": self.model,
                "analysis": "",
                "error": str(error),
            }

    def analyze_incident_fast(self, incident):
        """
        Force the lightweight Qwen model.
        """

        original_model = self.model

        try:
            self.model = self.FAST_MODEL
            self.provider.model = self.FAST_MODEL

            return self.analyze_incident(incident)

        finally:
            self.model = original_model
            self.provider.model = original_model

    def analyze_incident_advanced(self, incident):
        """
        Force the Llama model for deeper analysis.
        """

        original_model = self.model

        try:
            self.model = self.ADVANCED_MODEL
            self.provider.model = self.ADVANCED_MODEL

            return self.analyze_incident(incident)

        finally:
            self.model = original_model
            self.provider.model = original_model

    def analyze_incident_stream(self, incident):
        """
        Compatibility method.

        The project now prefers complete responses rather
        than streaming because complete responses are easier
        for the GUI to render reliably.
        """

        result = self.analyze_incident(incident)

        yield result
