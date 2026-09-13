import requests


class AIModelManager:
    """
    Manages locally available Ollama models.
    """

    def __init__(
        self,
        base_url="http://127.0.0.1:11434",
    ):
        self.base_url = base_url.rstrip("/")

    def get_models(self):
        """
        Return installed Ollama models.
        """
        try:
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=3,
            )

            response.raise_for_status()

            data = response.json()

            models = []

            for model in data.get("models", []):
                name = model.get("name")

                if name:
                    models.append(name)

            return models

        except requests.RequestException:
            return []

        except ValueError:
            return []

    def is_available(self):
        """
        Check whether Ollama is reachable.
        """
        try:
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=3,
            )

            return response.status_code == 200

        except requests.RequestException:
            return False

    def model_exists(self, model_name):
        """
        Check whether a specific model is installed.
        """
        return model_name in self.get_models()

    def get_default_model(self):
        """
        Select the best default model based on
        installed models.
        """

        models = self.get_models()

        preferred_models = [
            "qwen3:1.7b",
            "gemma3:1b",
            "qwen3:0.6b",
            "llama3.2:latest",
        ]

        for model in preferred_models:
            if model in models:
                return model

        if models:
            return models[0]

        return None
