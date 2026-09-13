import ipaddress
from datetime import datetime

from threat_intelligence.providers.abuseipdb import (
    AbuseIPDBProvider
)


class ThreatIntelligenceEnricher:
    """
    Threat Intelligence enrichment layer.

    Local classification is always performed.

    Public IPs can optionally be checked through
    configured external threat-intelligence providers.
    """

    def __init__(self):
        self.provider_name = "Local IP Intelligence"

        self.providers = [
            AbuseIPDBProvider()
        ]

    # ========================================================
    # IP VALIDATION
    # ========================================================

    def validate_ip(self, ip):

        if not ip:
            return False

        try:
            ipaddress.ip_address(ip)
            return True

        except ValueError:
            return False

    # ========================================================
    # IP CLASSIFICATION
    # ========================================================

    def classify_ip(self, ip):

        if not self.validate_ip(ip):
            return "INVALID"

        address = ipaddress.ip_address(ip)

        if address.is_loopback:
            return "LOOPBACK"

        if address.is_private:
            return "PRIVATE"

        if address.is_link_local:
            return "LINK_LOCAL"

        if address.is_multicast:
            return "MULTICAST"

        if address.is_reserved:
            return "RESERVED"

        if address.is_unspecified:
            return "UNSPECIFIED"

        return "PUBLIC"

    # ========================================================
    # LOCAL INTELLIGENCE
    # ========================================================

    def enrich_ip(self, ip):

        result = {
            "ip": ip,
            "valid": False,
            "classification": "INVALID",

            "is_private": False,
            "is_public": False,
            "is_loopback": False,
            "is_reserved": False,
            "is_multicast": False,

            "provider": self.provider_name,

            "reputation": "UNKNOWN",
            "malicious": None,
            "confidence": 0,

            "external_intelligence": None,

            "checked_at":
                datetime.utcnow().isoformat() + "Z"
        }

        # ----------------------------------------------------
        # Validate
        # ----------------------------------------------------

        if not self.validate_ip(ip):
            return result

        address = ipaddress.ip_address(ip)

        classification = self.classify_ip(ip)

        result["valid"] = True
        result["classification"] = classification

        result["is_private"] = address.is_private

        result["is_public"] = (
            classification == "PUBLIC"
        )

        result["is_loopback"] = (
            address.is_loopback
        )

        result["is_reserved"] = (
            address.is_reserved
        )

        result["is_multicast"] = (
            address.is_multicast
        )

        # ====================================================
        # LOCAL / NON-PUBLIC IP
        # ====================================================

        if classification == "PRIVATE":

            result["reputation"] = "LOCAL"
            result["malicious"] = None
            result["confidence"] = 100

            return result

        if classification == "LOOPBACK":

            result["reputation"] = "LOCAL"
            result["malicious"] = None
            result["confidence"] = 100

            return result

        if classification == "LINK_LOCAL":

            result["reputation"] = "LOCAL"
            result["malicious"] = None
            result["confidence"] = 100

            return result

        if classification == "RESERVED":

            result["reputation"] = "RESERVED"
            result["malicious"] = None
            result["confidence"] = 100

            return result

        if classification == "MULTICAST":

            result["reputation"] = "MULTICAST"
            result["malicious"] = None
            result["confidence"] = 100

            return result

        if classification == "UNSPECIFIED":

            result["reputation"] = "UNSPECIFIED"
            result["malicious"] = None
            result["confidence"] = 100

            return result

        # ====================================================
        # PUBLIC IP
        # ====================================================

        if classification == "PUBLIC":

            result = self._query_external_providers(
                ip,
                result
            )

        return result

    # ========================================================
    # EXTERNAL PROVIDERS
    # ========================================================

    def _query_external_providers(
        self,
        ip,
        result
    ):

        for provider in self.providers:

            try:

                if not provider.is_available():
                    continue

                intelligence = provider.lookup_ip(
                    ip
                )

                if not intelligence:
                    continue

                if not intelligence.get(
                    "success",
                    False
                ):
                    continue

                result["provider"] = intelligence.get(
                    "provider",
                    provider.name
                )

                result["reputation"] = intelligence.get(
                    "reputation",
                    "UNKNOWN"
                )

                result["malicious"] = intelligence.get(
                    "malicious"
                )

                result["confidence"] = intelligence.get(
                    "confidence",
                    0
                )

                result["external_intelligence"] = (
                    intelligence
                )

                return result

            except Exception as error:

                result["external_intelligence"] = {
                    "provider":
                        getattr(
                            provider,
                            "name",
                            "Unknown"
                        ),

                    "success": False,

                    "error":
                        str(error)
                }

        # ----------------------------------------------------
        # No provider available
        # ----------------------------------------------------

        result["provider"] = (
            "No external provider configured"
        )

        result["reputation"] = "UNKNOWN"
        result["malicious"] = None
        result["confidence"] = 0

        return result

    # ========================================================
    # INCIDENT ENRICHMENT
    # ========================================================

    def enrich_incident(self, incident):

        source_ip = incident.get(
            "source_ip"
        )

        intelligence = self.enrich_ip(
            source_ip
        )

        enriched_incident = dict(
            incident
        )

        enriched_incident[
            "threat_intelligence"
        ] = intelligence

        return enriched_incident


# ============================================================
# CONVENIENCE FUNCTIONS
# ============================================================

def enrich_ip(ip):

    enricher = ThreatIntelligenceEnricher()

    return enricher.enrich_ip(ip)


def enrich_incident(incident):

    enricher = ThreatIntelligenceEnricher()

    return enricher.enrich_incident(
        incident
    )
