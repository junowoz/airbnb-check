"""Small message catalogue (en / pt / es) and language detection."""
from __future__ import annotations

import os
from typing import Mapping

LANGS = ("en", "pt", "es")


def detect_lang(env: Mapping[str, str] | None = None) -> str:
    """Pick en/pt/es from LC_ALL, LC_MESSAGES, LANG (first non-empty wins); anything else is en."""
    env = os.environ if env is None else env
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        val = (env.get(var) or "").strip().lower()
        if val and val not in ("c", "posix"):
            for code in ("pt", "es"):
                if val.startswith(code):
                    return code
            return "en"
    return "en"


MSG: dict[str, dict[str, str]] = {
    "en": {
        "h_oui": "Vendor database", "h_net": "Network scan", "h_wifi": "Nearby Wi-Fi", "h_verdict": "Verdict",
        "h_checklist": "Physical checklist (do this too)",
        "p_oui": "[1/3] Vendor database...", "p_net": "[2/3] Scanning the network (2 discovery passes)...",
        "p_wifi": "[3/3] Checking nearby Wi-Fi...",
        "oui_fresh": "MAC vendor list is up to date.", "oui_ok": "Downloaded the MAC vendor list ({n} prefixes).",
        "oui_fail": "Could not download the vendor list ({err}); continuing without vendor names.",
        "oui_skip": "Offline mode: vendor list not updated.",
        "passes": "Discovery ran in {n} passes about {gap} s apart and results were merged, because some cameras sleep.",
        "wifi_seen": "{n} Wi-Fi networks seen, {k} with camera-like names.",
        "wifi_none": "No camera-like network names.",
        "wifi_redacted": "macOS hid {n} network names. Grant Location permission to your terminal in System Settings > "
                         "Privacy & Security > Location Services, then run again.",
        "wifi_unavail": "Could not list Wi-Fi networks: {err}",
        "wifi_flag": "SSID '{ssid}' looks like {hit}{strong}", "wifi_strong": " with a STRONG signal (probably inside the unit)",
        "overall": "Overall level: {level}",
        "v_high": "Something looks like a camera. Investigate it physically.",
        "v_medium": "No certain camera, but something is suspicious. Identify each flagged item.",
        "v_low": "No clear camera signals; only weak hints.",
        "v_clear": "No camera signals found. This does NOT prove the unit is camera-free.",
        "flagged": "Flagged:", "flagged_none": "Nothing flagged.",
        "limits_title": "What this check cannot see:",
        "limits": "A different VLAN or separate guest network than the one you joined|4G/cellular cameras or anything not on this Wi-Fi|"
                  "SD-card-only recorders|Devices that are powered off or asleep during the scan",
        "report_written": "Report written to {path}",
    },
    "pt": {
        "h_oui": "Base de fabricantes", "h_net": "Varredura da rede", "h_wifi": "Wi-Fi por perto", "h_verdict": "Veredito",
        "h_checklist": "Checklist físico (faça também)",
        "p_oui": "[1/3] Base de fabricantes...", "p_net": "[2/3] Varrendo a rede (2 passadas de descoberta)...",
        "p_wifi": "[3/3] Verificando Wi-Fi por perto...",
        "oui_fresh": "Lista de fabricantes (MAC) em dia.", "oui_ok": "Lista de fabricantes baixada ({n} prefixos).",
        "oui_fail": "Não foi possível baixar a lista de fabricantes ({err}); seguindo sem nomes de fabricantes.",
        "oui_skip": "Modo offline: lista de fabricantes não atualizada.",
        "passes": "A descoberta rodou em {n} passadas com cerca de {gap} s de intervalo e os resultados foram unidos, porque algumas câmeras dormem.",
        "wifi_seen": "{n} redes Wi-Fi vistas, {k} com nome de câmera.",
        "wifi_none": "Nenhuma rede com nome de câmera.",
        "wifi_redacted": "O macOS escondeu {n} nomes de rede. Dê permissão de Localização ao seu terminal em Ajustes do Sistema > "
                         "Privacidade e Segurança > Serviços de Localização e rode de novo.",
        "wifi_unavail": "Não foi possível listar redes Wi-Fi: {err}",
        "wifi_flag": "SSID '{ssid}' parece {hit}{strong}", "wifi_strong": " com sinal FORTE (provavelmente dentro do imóvel)",
        "overall": "Nível geral: {level}",
        "v_high": "Algo parece uma câmera. Investigue fisicamente.",
        "v_medium": "Nenhuma câmera certa, mas há algo suspeito. Identifique cada item marcado.",
        "v_low": "Nenhum sinal claro de câmera; só indícios fracos.",
        "v_clear": "Nenhum sinal de câmera encontrado. Isso NÃO prova que o imóvel está livre de câmeras.",
        "flagged": "Marcado:", "flagged_none": "Nada marcado.",
        "limits_title": "O que esta verificação não enxerga:",
        "limits": "Outra VLAN ou rede de hóspedes separada da que você entrou|Câmeras 4G/celular ou qualquer coisa fora deste Wi-Fi|"
                  "Gravadores só com cartão SD|Aparelhos desligados ou dormindo durante a varredura",
        "report_written": "Relatório gravado em {path}",
    },
    "es": {
        "h_oui": "Base de fabricantes", "h_net": "Escaneo de la red", "h_wifi": "Wi-Fi cercano", "h_verdict": "Veredicto",
        "h_checklist": "Lista de revisión física (hazla también)",
        "p_oui": "[1/3] Base de fabricantes...", "p_net": "[2/3] Escaneando la red (2 pasadas de descubrimiento)...",
        "p_wifi": "[3/3] Revisando el Wi-Fi cercano...",
        "oui_fresh": "Lista de fabricantes (MAC) al día.", "oui_ok": "Lista de fabricantes descargada ({n} prefijos).",
        "oui_fail": "No se pudo descargar la lista de fabricantes ({err}); sigo sin nombres de fabricante.",
        "oui_skip": "Modo sin conexión: lista de fabricantes sin actualizar.",
        "passes": "El descubrimiento corrió en {n} pasadas separadas por unos {gap} s y se unieron los resultados, porque algunas cámaras duermen.",
        "wifi_seen": "{n} redes Wi-Fi vistas, {k} con nombre de cámara.",
        "wifi_none": "Ninguna red con nombre de cámara.",
        "wifi_redacted": "macOS ocultó {n} nombres de red. Da permiso de Ubicación a tu terminal en Ajustes del Sistema > "
                         "Privacidad y seguridad > Servicios de localización y vuelve a ejecutar.",
        "wifi_unavail": "No se pudieron listar las redes Wi-Fi: {err}",
        "wifi_flag": "SSID '{ssid}' parece {hit}{strong}", "wifi_strong": " con señal FUERTE (probablemente dentro del alojamiento)",
        "overall": "Nivel general: {level}",
        "v_high": "Algo parece una cámara. Investígalo físicamente.",
        "v_medium": "Ninguna cámara segura, pero hay algo sospechoso. Identifica cada elemento marcado.",
        "v_low": "Sin señales claras de cámara; solo indicios débiles.",
        "v_clear": "No se encontraron señales de cámara. Esto NO prueba que el alojamiento esté libre de cámaras.",
        "flagged": "Marcado:", "flagged_none": "Nada marcado.",
        "limits_title": "Lo que esta revisión no puede ver:",
        "limits": "Otra VLAN o red de invitados separada de la que usaste|Cámaras 4G/celular o cualquier cosa fuera de este Wi-Fi|"
                  "Grabadoras solo con tarjeta SD|Aparatos apagados o dormidos durante el escaneo",
        "report_written": "Informe guardado en {path}",
    },
}


def t(lang: str, key: str, **kw: object) -> str:
    s = MSG.get(lang, MSG["en"]).get(key) or MSG["en"][key]
    return s.format(**kw) if kw else s


def limits(lang: str) -> list[str]:
    return t(lang, "limits").split("|")
