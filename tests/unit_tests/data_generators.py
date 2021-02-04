def generate_vulnerability_message(severity: str):
    return {
        "name": "generated",
        "severity": severity,
        "via": [
            "micromatch"
        ],
        "effects": [
            "chokidar"
        ],
        "range": "1.2.0 - 1.3.2",
        "nodes": [
            "node_modules/anymatch"
        ],
        "fixAvailable": True
    }.copy()
