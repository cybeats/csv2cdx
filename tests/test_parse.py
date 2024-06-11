import pytest
import csv2cdx.parse
from csv2cdx.parse import Parser
import pandas as pd

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

json_file = "test-data/example_config.json"
csv_file = "test-data/example_data.csv"

parser = Parser(testargs)


    
def test_csv_parse():
    ret = parser.read_csv(csv_file)
    assert type(ret) == pd.DataFrame

def test_json_parse():
    ret = parser.read_json(json_file)
    assert type(ret) == dict


def test_json_info():
    ret = parser.read_json(json_file)
    
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
    
    assert ret == check



def test_csv_info():
    ret = parser.read_csv(csv_file)

    csv_data = pd.Series(
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
    
    assert ret.iloc[0].to_dict() == csv_data.to_dict()




def test_arg_type():
    
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
    
    ret = parser.get_args(testargs)
    assert type(ret) == dict



def test_arg_info():
    
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
    
    ret = parser.get_args(testargs)
    assert ret == testout  








        



