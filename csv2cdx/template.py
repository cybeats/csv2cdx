import json
import os

filename = "config_template.json"

filepath = f"{os.getcwd()}/{filename}"

data = {
  "api_url": None,
  "component_configuration": {
    "name": None,
    "version": None,
    "type": None,
    "bom-ref": None,
    "group": None,
    "publisher": None,
    "purl": None,
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
    ],
    "mime type": None,
    "description": None,
    "author": None,
    "cpe": None,
    "swid": None,
    "pedigree": None,
    "components": None,
    "evidence": None,
    "releaseNotes": None,
    "copyright": None
  }
}


def create_template_file(filename):
    if filename is None:
        filename = "config_template"
    
    filepath = f"{os.getcwd()}/{filename}.json"
    with open(filepath, "w") as fp:
        json.dump(data, fp, indent=4)