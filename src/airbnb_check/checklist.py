"""Physical inspection checklist (en / pt / es)."""
from __future__ import annotations

CHECKLISTS: dict[str, list[tuple[str, list[str]]]] = {
    "en": [
        ("1. Dark-room sweep", [
            "Lights off, curtains closed. Slowly sweep a flashlight across the room: camera lenses glint back as a small bright dot.",
            "Open your phone's FRONT camera (many show infrared) and look for faint purple/white dots: IR LEDs of night-vision cameras.",
            "Look for tiny steady or blinking LEDs where no device should be.",
        ]),
        ("2. Typical hiding spots", [
            "Smoke detectors and sensors, clocks, USB chargers and power strips, speakers, picture frames.",
            "Wi-Fi routers, TV boxes, soundbars, air purifiers, tissue boxes, plants, books, shelves facing the bed or shower.",
            "Mirrors facing the bed or shower: press a fingertip on the glass; a gap between finger and reflection is normal for a normal mirror, no gap is suspicious for two-way mirrors.",
            "Anything pointing at the bed, shower, toilet or changing area; devices that are unplugged or have no reason to be there.",
        ]),
        ("3. Cross-checks", [
            "Run `airbnb-check` on the Wi-Fi and investigate every MEDIUM/HIGH device.",
            "Check the listing: Airbnb requires disclosure of cameras, and bans them indoors since 2024.",
        ]),
        ("4. If you find something", [
            "Do not touch or unplug it. Photograph it and where it sits. Keep the evidence.",
            "Leave if you feel unsafe. Report in the Airbnb app (and ask for a refund).",
            "Cameras in a bedroom or bathroom are a crime in most places: call the police.",
        ]),
    ],
    "pt": [
        ("1. Varredura no escuro", [
            "Apague as luzes e feche as cortinas. Passe uma lanterna devagar pelo ambiente: a lente de uma câmera devolve um pontinho brilhante.",
            "Abra a câmera FRONTAL do celular (muitas enxergam infravermelho) e procure pontos roxos/brancos fracos: LEDs IR de visão noturna.",
            "Procure LEDs minúsculos, fixos ou piscando, onde não deveria haver aparelho.",
        ]),
        ("2. Esconderijos comuns", [
            "Detectores de fumaça, relógios, carregadores USB e réguas de energia, caixas de som, porta-retratos.",
            "Roteadores, TV box, soundbar, purificadores de ar, caixa de lenços, plantas, livros, prateleiras apontadas para a cama ou o chuveiro.",
            "Espelhos virados para a cama ou o chuveiro: encoste a ponta do dedo no vidro; se não houver espaço entre o dedo e o reflexo, desconfie de espelho falso.",
            "Qualquer coisa apontada para cama, chuveiro, vaso ou área de troca de roupa; aparelhos desligados da tomada ou sem motivo para estar ali.",
        ]),
        ("3. Confirmações", [
            "Rode `airbnb-check` no Wi-Fi e investigue todo dispositivo MEDIUM/HIGH.",
            "Veja o anúncio: o Airbnb exige aviso de câmeras e proíbe câmeras internas desde 2024.",
        ]),
        ("4. Se encontrar algo", [
            "Não mexa nem desligue. Fotografe o aparelho e o local. Guarde as provas.",
            "Saia se não se sentir seguro. Denuncie pelo app do Airbnb (e peça reembolso).",
            "Câmera em quarto ou banheiro é crime na maioria dos lugares: chame a polícia.",
        ]),
    ],
    "es": [
        ("1. Barrido en la oscuridad", [
            "Apaga las luces y cierra las cortinas. Pasa una linterna despacio por la habitación: el lente de una cámara devuelve un puntito brillante.",
            "Abre la cámara FRONTAL del móvil (muchas ven infrarrojo) y busca puntos morados/blancos tenues: LEDs IR de visión nocturna.",
            "Busca LEDs diminutos, fijos o parpadeantes, donde no debería haber ningún aparato.",
        ]),
        ("2. Escondites típicos", [
            "Detectores de humo, relojes, cargadores USB y regletas, altavoces, marcos de fotos.",
            "Routers, TV box, barras de sonido, purificadores de aire, cajas de pañuelos, plantas, libros, estantes que apuntan a la cama o la ducha.",
            "Espejos frente a la cama o la ducha: apoya la yema del dedo en el cristal; si no hay espacio entre el dedo y el reflejo, sospecha de espejo falso.",
            "Cualquier cosa que apunte a la cama, ducha, inodoro o zona para cambiarse; aparatos desenchufados o sin motivo para estar ahí.",
        ]),
        ("3. Verificaciones", [
            "Ejecuta `airbnb-check` en el Wi-Fi e investiga todo dispositivo MEDIUM/HIGH.",
            "Revisa el anuncio: Airbnb exige avisar de las cámaras y las prohíbe en interiores desde 2024.",
        ]),
        ("4. Si encuentras algo", [
            "No lo toques ni lo desenchufes. Fotografía el aparato y su ubicación. Guarda las pruebas.",
            "Vete si no te sientes seguro. Denuncia en la app de Airbnb (y pide reembolso).",
            "Una cámara en dormitorio o baño es delito en la mayoría de lugares: llama a la policía.",
        ]),
    ],
}


def render(lang: str = "en") -> str:
    sections = CHECKLISTS.get(lang, CHECKLISTS["en"])
    out = []
    for title, items in sections:
        out.append(title)
        out.extend(f"  [ ] {i}" for i in items)
        out.append("")
    return "\n".join(out).rstrip()
