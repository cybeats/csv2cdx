import json
from pathlib import Path

default_filename = "config_template.json"

configs = {
    "bom-ref": None,
    "name": None,
    "version": None,
    "type":None,
    "group": None,
    "publisher": None,
    "purl": None,
    "description": None,
    "author": None,
    "cpe": None,
    "copyright": None,
    "supplier":{
        "supplier_name":None,
        "supplier_urls":[None],
        "supplier_contacts":[
            {
                "contact_name":None,
                "contact_email":None,
                "contact_phone":None
            }
        ]
    },
    "licenses": [
      {
        "license_name": None,
        "license_url": None,
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




