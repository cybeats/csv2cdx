import json
from pathlib import Path

default_filename = "config_template.json"

configs = {
    "bom-ref": None,
    "name": None,
    "version": None,
    "group": None,
    "publisher": None,
    "purl": None,
    "mime type": None,
    "description": None,
    "author": None,
    "cpe": None,
    "swid": None,
    "pedigree": None,
    "components": None,
    "evidence": None,
    "releaseNotes": None,
    "copyright": None,
    "supplier":None,
    "licenses": [
      {
        "license_name": None,
        "license_url": None,
        "license_id": None
      }
    ],
    "hashes": [
      {
        "hash_alg": None,
        "hash_content": None
      }
    ],
    "externalReferences": [
      {
        "er_type": None,
        "er_url": None
      }
    ]
}


def create_template_file(filename):
    file_name = filename if filename is not None else default_filename
    config_file = Path(file_name)
    config_file.write_text(json.dumps(configs, indent=4))




