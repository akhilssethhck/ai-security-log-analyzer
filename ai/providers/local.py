import os
import requests


class LocalOllamaProvider:
    """
    Lightweight Ollama provider optimized for local CPU inference.
    """

    def __init__(
        self,
        base_url=None,
        model=None,
        timeout=None,
    ):
        self.base_url = (
            base_url
            or os.getenv("OLLAMA_BASE_URL")
            or "http://127.0.0.1:11434"
        ).rstrip("/")

        self.model = (
            model
            or os.getenv("OLLAMA_MODEL")
            or "qwen3:1.7b"
        )

        self.timeout = int(
            timeout
            or os.getenv("OLLAMA_TIMEOUT", "180")
        )

    def is_available(self):
        try:
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=5,
            )
            return response.ok
        except requests.RequestException:
            return False

    def list_models(self):
        try:
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=5,
            )
            response.raise_for_status()

            data = response.json()

            return [
                model.get("name")
                for model in data.get("models", [])
                if model.get("name")
            ]

        except (requests.RequestException, ValueError):
            return []

    def generate(
        self,
        prompt,
        model=None,
        temperature=0.1,
        max_tokens=350,
    ):
        selected_model = model or self.model

        payload = {
            "model": selected_model,
            "prompt": prompt,

            # Lower randomness = more consistent SOC analysis.
            "stream": False,
            "keep_alive": "15m",
            "think": False,

            "options": {
                "temperature": temperature,

                # Important for CPU performance.
                "num_predict": 256,

                # Don't unnecessarily process huge contexts.
                "num_ctx": 1024,
            },
        }

        response = requests.post(
            f"{self.base_url}/api/generate",
            json=payload,
            timeout=self.timeout,
        )

        response.raise_for_status()

        data = response.json()

        return {
            "model": data.get("model", selected_model),
            "response": data.get("response", "").strip(),
            "total_duration": data.get("total_duration"),
            "load_duration": data.get("load_duration"),
            "prompt_eval_count": data.get("prompt_eval_count"),
            "eval_count": data.get("eval_count"),
        }
