from abc import ABC, abstractmethod


class ThreatIntelProvider(ABC):
    """
    Base interface for threat-intelligence providers.

    Every external provider should implement this interface.
    """

    name = "Unknown Provider"

    @abstractmethod
    def lookup_ip(self, ip):
        """
        Look up an IP address.

        Returns a dictionary containing normalized
        threat-intelligence information.
        """
        raise NotImplementedError
