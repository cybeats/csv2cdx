
import pandas as pd
import json
import cyclonedx
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import ComponentType, Component
from cyclonedx.model import OrganizationalEntity, OrganizationalContact, XsUri
from uuid import uuid4
from cyclonedx.output import get_instance, BaseOutput, OutputFormat
import re
from packageurl import PackageURL
import pathlib



class Builder:

    def __init__(self, csv_data :dict, json_data :dict) -> None:

        self.name = None
        self.version = None
        self.package = None

        self.supplier = None
        self.supplier_urls = None
        self.supplier_contact = None
        self.supplier_contact_name = None
        self.supplier_contact_phone = None
        self.supplier_contact_email = None
        self.comps = []

        self.purl = None
        self.swid = None
        self.cpe = None
        self.type = None

        self.values = csv_data
        self.config = json_data
        self.control = self.config.get("configuration")
        self.manufacturer = {}

        self.bom =  Bom()

        self.check = [
                        "application", 
                        "framework", 
                        "library", 
                        "container", 
                        "operating-system", 
                        "device", 
                        "firmware", 
                        "file"
                    ]

    def if_exist(self, array, arg):
        if arg in array:
            return True
        else:
            return False

    def get_component_param(self,array, parameter):
        if self.if_exist(array, parameter) == False:
            return None
        pass

    def get_config_param(self, array, parameter):
        if self.if_exist(array, parameter) == False:
            return None
        pass

    def check_in(self, term :str, assay :dict):
        if term not in assay:
            print("WARNING {} not present".format(term))

    
    def cpe_wildcard(cpe :str):
        cpe = cpe.split(":")
        if "cpe" != cpe[0]:
            return None 
        cpe[-1] = ".*.*.*.*.*.*"
        return cpe.join() 


    def make_purl(self, package, name, version):
        if package == None:
            package = 'generic'
        purl = "pkg:{}/{}@{}".format(package, name, version)
        purl_formatted  = PackageURL.from_string(purl)
        return purl_formatted


    


    def build_components(self, val):

        for key in val:
            name = val[key].get(self.control.get("name"))
            version = val[key].get(self.control.get("version"))

            if "supplier_urls" in val[key]:
                
                self.supplier_urls = XsUri(val[key].get("supplier_urls"))

           
           
            if "supplier_contact_name" in val[key]:
                contacts = OrganizationalContact(
                                                    name=val[key].get("supplier_name", None), 
                                                    email=val[key].get("supplier_contact_email", None), 
                                                    phone=val[key].get("supplier_contact_phone", None)
                                                )
            else:
                contacts = None
            
            if "supplier_contact_name" in val[key]:           
                self.supplier = OrganizationalEntity(
                                                        name=val[key].get("supplier_name", None), 
                                                        urls=  self.supplier_urls, 
                                                        contacts= contacts
                                                    )
            else:
                self.supplier = None      
        

            self.cpe = val[key].get(self.control.get("cpe"))


            name = val[key].get(self.control.get("name"))
            version = val[key].get(self.control.get("version"))
            
            
            if self.config.get('add_purl')  is True:
                self.purl = self.make_purl(self.config.get("package_type"), name, version) 

            
            if self.config.get('wildcard') == "true":
                self.cpe = self.cpe_wildcard(self.cpe) 

            self.type=ComponentType(val[key].get(self.control.get('type')))

            self.comps.append(
                                Component(
                                            name= name,       
                                            version=version, 
                                            purl=self.purl, 
                                            type=self.type, 
                                            supplier=self.supplier, 
                                            swid=val[key].get(self.control.get("swid", None)), 
                                            cpe=self.cpe

                                        )
                            )

            
   
   
   
    def create_metadata(self, config:dict):

        if "type" not in config:
            print("WARNING, NO TYPE GIVEN")  

        if config["type"] not in self.check:
            print("ERROR, UNKNOWN TYPE")
            exit()

        version = config.get("sbom_component_version", None)

        if config.get("manufacturer_name", None) is not None:
            self.bom.metadata.manufacture = OrganizationalEntity(
                                                    name=config.get("manufacturer_name", None),
                                                    urls= config.get("manufacturer_url", None), 
                                                    contacts= config.get("manufacturer_contact", None)
                                               )
        
        self.bom.metadata.component = Component(
                                                    name=config.get("sbom_component_name", None), 
                                                    type=ComponentType(config.get("sbom_type", None)),
                                                    namespace= config.get("namespace", None),
                                                    version= version                                                   
                                                )   
    
    
    def create_sbom(self):
        self.build_components(self.values)
        self.create_metadata(self.config)
        self.bom.components=self.comps
        outputter: BaseOutput = get_instance(bom=self.bom, output_format=OutputFormat.JSON)
        bom_json: str = outputter.output_as_string()
        parsed = json.loads(bom_json)
        newbom = json.dumps(parsed, indent=4)
        with open("sbom.json", "w") as nb:
            nb.write(newbom)
  

