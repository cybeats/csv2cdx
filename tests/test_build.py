import pytest
import csv2cdx.build
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


def test_hash_algo():
    algo = "SHA-1"
    ret = builder.get_hash_algo(algo)
    comp = HashAlgorithm(algo)
    assert ret == comp


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

    ret = builder.build_component(1, 1, data, conf)

    assert ret == comp



def test_make_purl():
    purl = PackageURL.from_string("pkg:generic/Component_1@5.5.8")
    testpurl = builder.make_purl("generic", "Component_1", "5.5.8")
    assert purl == testpurl



def test_cpe_wildcard():
    cpe_w = "cpe:2.3:a:python:cpython:3.12.0:alpha_7"
    cpe_test = "cpe:2.3:a:python:cpython:3.12.0:*:*:*:*:*:*"
    cpe = builder.cpe_wildcard(cpe_w)
    assert cpe == cpe_test


def test_contacts():
    name = "name"
    email = "email@gmail.com"
    phone = "111-111-1111"

    test = OrganizationalContact(   name=name, 
                                    email=email, 
                                    phone=phone
                                )
    ret = builder.build_contacts(name=name, email=email, phone=phone)


    assert ret == test

def test_supplier():

    testname = "name"
    email = "email@gmail.com"
    phone = "111-111-1111"
    url = "www.name.com"

    contacts = [
                OrganizationalContact(  name=testname, 
                                        email=email, 
                                        phone=phone
                                    ) 
            ]
    
    urls = [XsUri(url)]

    supplier = OrganizationalEntity(
                                        name=testname, 
                                        urls=urls, 
                                        contacts=contacts
                                    )
    
    ret = builder.build_supplier(testname, urls, contacts)


    assert ret == supplier

def test_url():
    url = "www.name.com"
    url_test = XsUri(url)
    ret = builder.build_url(url)
    assert ret == url_test

def test_exref():
    type_ref = ExternalReferenceType("website")
    url_s = "www.name.com"
    url = XsUri(url_s)
    test = ExternalReference(
                                        type=type_ref, 
                                        url=url
                                    )
    
    
    ref = {
            "er_type": 1,
            "er_url": 2

        }

    data = {
               1: "website",
               2: "www.name.com"

            }
    ret = builder.get_exRef(ref, data)
    

    assert ret == test




    




