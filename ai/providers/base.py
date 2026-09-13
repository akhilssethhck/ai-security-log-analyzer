from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """
    Common interface for all AI/LLM providers.
    """

    name = "Unknown LLM Provider"

    @abstractmethod
    def is_available(self):
        """
        Return True when the provider is configured and usable.
        """
        raise NotImplementedError

    @abstractmethod
    def analyze(self, system_prompt, user_prompt):
        """
        Send security context to the LLM and return its response.
        """
        raise NotImplementedError
