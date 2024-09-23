import pytest
from csv2cdx.build import Builder
from csv2cdx.parse import Parser
import pandas as pd
from packageurl import PackageURL

from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import ComponentType, Component
from cyclonedx.model import HashAlgorithm, HashType, ExternalReference, ExternalReferenceType, XsUri
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.model.contact import OrganizationalContact
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.output import BaseOutput, OutputFormat

json_file = "test-data/example_config.json"
csv_file = "test-data/example_data.csv"

csv_data_series = pd.Series(
                                {
                                    "Component":"Component 1", 
                                    "Version":"5.5.8", 
                                    "Description":"Description 1",
                                    "Organization":"Organization 1",
                                    "Algorithm":"SHA-1",
                                    "Hash":"0a55e5f4effb45fbc8220a8921e5b0cf214452df",
                                    "PURL":"pkg:generic/Component_1@5.5.8"
                                }
                            )  


check = {
    "api_url": None,
    "component_configuration": {
                                "name": "Component",
                                "version": "Version",
                                "type": None,
                                "bom-ref": None,
                                "group": None,
                                "publisher": None,
                                "purl": "PURL",
                                "licenses": [
                                                {
                                                    "license_name": None,
                                                    "license_url": None,
                                                    "license_id": None
                                                }
                                ],
                                "hashes": [
                                            {
                                                "hash_alg": "Algorithm",
                                                "hash_content": "Hash"
                                            }
                                ],
                                "externalReferences": [
                                            {
                                                "er_type": None,
                                                "er_url": None
                                            }
                                ],
                                "mime type": None,
                                "description": "Description",
                                "author": "Organization",
                                "cpe": None,
                                "swid": None,
                                "pedigree": None,
                                "components": None,
                                "evidence": None,
                                "releaseNotes": None,
                                "copyright": None
                                }
        }
    

testargs = {
            'subcommand': 'build', 
            "c": "test-data/example_config.json", 
            "f": "test-data/example_data.csv", 
            'pt': 'generic', 
            't': 'application', 
            'pn': 'example', 
            'pv': '1.0.0', 
            'mn': None, 
            'sn': None, 
            'ns': None, 
            'cw': None, 
            'ap': False, 
            'cnt': False, 
            'api': False, 
            'url': None, 
            'ak': None, 
            'sk': None
        }

testout = {
                "json":"test-data/example_config.json", 
                "file": "test-data/example_data.csv", 
                "sbom_type": "application", 
                "sbom_name": "example", 
                "sbom_version": "1.0.0", 
                "package_type": "generic",
                "manufacturer_name" : None,
                "supplier_name":None,
                "namespace":None,
                "cpe_wildcard":None,
                "add_purl":False,
                "csv_no_title":False,
                "use_api":False,
                "api_url":None,
                "access_key":None,
                "secret_key":None 

            }

 



parser = Parser(testargs)

arg_data = parser.get_args(parser.args)
csv_data = parser.read_csv(csv_file)
json_data = parser.read_json(json_file)

builder = Builder(arg_data, csv_data, json_data)



def test_component():
    csv_data_frame = pd.DataFrame(
                                {
                                    "Component":["Component 1"], 
                                    "Version":["5.5.8"], 
                                    "Description":["Description 1"],
                                    "Organization":["Organization 1"],
                                    "Algorithm":["SHA-1"],
                                    "Hash":["0a55e5f4effb45fbc8220a8921e5b0cf214452df"],
                                    "PURL":["pkg:generic/Component_1@5.5.8"]
                                }
                            )


    comp = Component(
                    name="Component 1",
                    version="5.5.8",
                    description="Description 1",
                    author="Organization 1",
                    hashes=[    
                               HashType(
                                            alg=HashAlgorithm("SHA-1"), 
                                            content="0a55e5f4effb45fbc8220a8921e5b0cf214452df"
                                        ) 
                            ],
                    purl=PackageURL.from_string("pkg:generic/Component_1@5.5.8")
                )
     
    data = next(csv_data_frame.iterrows())[1]
    
    conf = check.get("component_configuration")

    ret = builder.get_component(data, conf)

    assert ret == comp
