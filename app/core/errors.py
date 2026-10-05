"""User-facing error model.

Every error raised by the application carries three human-readable parts, shown
as-is in the interface:

* ``message`` - ERREUR : what went wrong;
* ``cause``   - CAUSE POSSIBLE : the most likely reason;
* ``action``  - ACTION : what the user should do.

Raw Python exceptions are never sent to the UI; ``detail`` only contains
sanitized technical context (e.g. the tool's stderr with serials masked).
"""

from __future__ import annotations

from typing import Any


class LMSError(Exception):
    code = "internal_error"
    http_status = 500
    default_message = "Une erreur interne est survenue."
    default_cause = "Erreur inattendue dans l'application."
    default_action = "Consultez l'onglet Logs pour le détail technique puis réessayez."

    def __init__(
        self,
        message: str | None = None,
        *,
        cause: str | None = None,
        action: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.message = message or self.default_message
        self.cause = cause or self.default_cause
        self.action = action or self.default_action
        self.detail = detail
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "cause": self.cause,
            "action": self.action,
            "detail": self.detail,
        }


class InvalidInputError(LMSError):
    code = "invalid_input"
    http_status = 400
    default_message = "Paramètre invalide."
    default_cause = "La valeur fournie ne respecte pas le format attendu."
    default_action = "Vérifiez la saisie puis réessayez."


class CommandNotAllowedError(LMSError):
    code = "command_not_allowed"
    http_status = 403
    default_message = "Commande refusée par la liste blanche."
    default_cause = "Seules les commandes ADB/Fastboot explicitement autorisées peuvent être exécutées."
    default_action = "Cette opération n'est pas prise en charge par le logiciel."


class ToolNotFoundError(LMSError):
    code = "tool_not_found"
    http_status = 503
    default_message = "Outil Android Platform Tools introuvable."
    default_cause = "adb/fastboot n'est pas installé ou n'est pas dans le PATH."
    default_action = (
        "Installez les Android Platform Tools officielles (voir README) ou renseignez LMS_PLATFORM_TOOLS_DIR."
    )


class ToolTimeoutError(LMSError):
    code = "tool_timeout"
    http_status = 504
    default_message = "La commande n'a pas répondu à temps."
    default_cause = "Le téléphone ne répond pas ou la connexion USB est instable."
    default_action = "Vérifiez le câble USB, déverrouillez l'écran du téléphone puis réessayez."


class ToolExecutionError(LMSError):
    code = "tool_execution_failed"
    http_status = 502
    default_message = "La commande ADB/Fastboot a échoué."
    default_cause = "L'outil a renvoyé une erreur."
    default_action = "Consultez le détail technique et l'onglet Logs."


class PathSecurityError(LMSError):
    code = "path_rejected"
    http_status = 400
    default_message = "Chemin de fichier refusé."
    default_cause = "Le chemin demandé sort du répertoire autorisé."
    default_action = "Choisissez un fichier ou un dossier situé dans le répertoire prévu."


class CSRFError(LMSError):
    code = "request_rejected"
    http_status = 403
    default_message = "Requête refusée."
    default_cause = "La requête ne provient pas de l'interface LUNATIC MOBILE SECURITY."
    default_action = "Rechargez l'interface puis réessayez."


class DeviceNotFoundError(LMSError):
    code = "device_not_found"
    http_status = 404
    default_message = "Aucun appareil prêt n'a été détecté."
    default_cause = (
        "Le téléphone n'est pas branché, le débogage USB est désactivé ou le câble ne transmet pas les données."
    )
    default_action = (
        "Branchez le téléphone avec un câble USB de données, activez « Débogage USB » dans "
        "Paramètres › Système › Options pour les développeurs, puis actualisez."
    )


class MultipleDevicesError(LMSError):
    code = "multiple_devices"
    http_status = 409
    default_message = "Plusieurs appareils sont connectés."
    default_cause = "L'opération doit cibler un seul appareil."
    default_action = "Sélectionnez l'appareil voulu dans la page Appareils, ou débranchez les autres."


class DeviceNotReadyError(LMSError):
    code = "device_not_ready"
    http_status = 409
    default_message = "L'appareil n'est pas prêt."
    default_cause = "Le téléphone est détecté mais ne peut pas être interrogé dans son état actuel."
    default_action = "Suivez l'action indiquée pour cet appareil dans la page Appareils."
