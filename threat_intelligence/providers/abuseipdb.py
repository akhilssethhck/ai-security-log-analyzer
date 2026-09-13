import os
import requests

from threat_intelligence.providers.base import ThreatIntelProvider


class AbuseIPDBProvider(ThreatIntelProvider):
    """
    AbuseIPDB threat-intelligence provider.

    The API key is read from the environment variable:

        ABUSEIPDB_API_KEY
    """

    name = "AbuseIPDB"

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, timeout=10):
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")
        self.timeout = timeout

    # ========================================================
    # AVAILABILITY
    # ========================================================

    def is_available(self):
        """
        Check whether the AbuseIPDB API key is configured.
        """

        return bool(self.api_key)

    # ========================================================
    # IP LOOKUP
    # ========================================================

    def lookup_ip(self, ip):

        if not self.is_available():

            return {
                "provider": self.name,
                "ip": ip,
                "available": False,
                "success": False,
                "reputation": "NOT_CONFIGURED",
                "malicious": None,
                "confidence": 0,
                "error": "ABUSEIPDB_API_KEY is not configured.",
            }

        headers = {
            "Accept": "application/json",
            "Key": self.api_key,
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
        }

        try:

            response = requests.get(
                self.API_URL,
                headers=headers,
                params=params,
                timeout=self.timeout,
            )

            if response.status_code != 200:

                return {
                    "provider": self.name,
                    "ip": ip,
                    "available": True,
                    "success": False,
                    "reputation": "UNKNOWN",
                    "malicious": None,
                    "confidence": 0,
                    "error":
                        f"API returned HTTP "
                        f"{response.status_code}",
                }

            data = response.json()

            result = data.get(
                "data",
                {}
            )

            abuse_score = result.get(
                "abuseConfidenceScore",
                0
            )

            total_reports = result.get(
                "totalReports",
                0
            )

            country_code = result.get(
                "countryCode"
            )

            isp = result.get(
                "isp"
            )

            domain = result.get(
                "domain"
            )

            usage_type = result.get(
                "usageType"
            )

            is_whitelisted = result.get(
                "isWhitelisted"
            )

            # ------------------------------------------------
            # Normalize reputation
            # ------------------------------------------------

            if abuse_score >= 75:

                reputation = "MALICIOUS"
                malicious = True

            elif abuse_score >= 25:

                reputation = "SUSPICIOUS"
                malicious = None

            else:

                reputation = "LOW_RISK"
                malicious = False

            return {
                "provider": self.name,
                "ip": ip,
                "available": True,
                "success": True,

                "reputation": reputation,
                "malicious": malicious,

                "confidence": abuse_score,

                "abuse_confidence_score":
                    abuse_score,

                "total_reports":
                    total_reports,

                "country_code":
                    country_code,

                "isp":
                    isp,

                "domain":
                    domain,

                "usage_type":
                    usage_type,

                "is_whitelisted":
                    is_whitelisted,
            }

        except requests.exceptions.Timeout:

            return {
                "provider": self.name,
                "ip": ip,
                "available": True,
                "success": False,
                "reputation": "UNKNOWN",
                "malicious": None,
                "confidence": 0,
                "error": "Threat-intelligence request timed out.",
            }

        except requests.exceptions.RequestException as error:

            return {
                "provider": self.name,
                "ip": ip,
                "available": True,
                "success": False,
                "reputation": "UNKNOWN",
                "malicious": None,
                "confidence": 0,
                "error":
                    f"Network error: {error}",
            }

        except ValueError:

            return {
                "provider": self.name,
                "ip": ip,
                "available": True,
                "success": False,
                "reputation": "UNKNOWN",
                "malicious": None,
                "confidence": 0,
                "error":
                    "Provider returned invalid JSON.",
            }
