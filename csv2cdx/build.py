import pandas as pd
import json
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import ComponentType, Component
from cyclonedx.model import OrganizationalEntity, OrganizationalContact, XsUri
from cyclonedx.model import HashAlgorithm, HashType, ExternalReference, ExternalReferenceType
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.output import get_instance, BaseOutput, OutputFormat
from packageurl import PackageURL
from pathlib import Path
from time import sleep
import os
import warnings
from .cy_api import cybeats_API
#warnings.filterwarnings("ignore", message="The Component this BOM is describing None has no defined dependencies which means the Dependency Graph is incomplete - you should add direct dependencies to this Componentto complete the Dependency Graph data.")

lc_factory = LicenseFactory()


class Builder:
    def __init__(self, arg_data: dict,  csv_data :pd.DataFrame, json_data :dict):
        
        self.arg_data = arg_data
        self.csv_data = csv_data
        self.json_data = json_data
        self.api_config = self.json_data.get("api")
        if self.arg_data.get("use_api") is True:
            self.url_json = self.json_data.get("api_url")
            self.url_arg = self.arg_data.get("api_url")
            self.api_url = self.url_arg if self.url_arg is not None else self.url_json
            self.api_access_key = self.arg_data.get("access_key")
            self.api_secret_key = self.arg_data.get("secret_key")
            if self.api_url is not None and self.api_access_key is not None and self.api_secret_key is not None:
                self.api = cybeats_API(api_url=self.api_url, access_key=self.api_access_key, secret_key=self.api_secret_key, package_type=arg_data.get("package_type"))
            else:
                self.api = None
        else:
            self.api = None

        self.output_file = Path(self.arg_data.get("file"),"").stem + "_sbom.json"



    def get_hash_algo(self, algorithm):
        res=None
        try:
            res = HashAlgorithm(algorithm)
        except:
            #res = None
            pass
        return res
    
        
   
    def get_hashes(self, hashes, csv_data) -> list:
        hashes = [self.get_hash(hash, csv_data) for hash in hashes]
        hashes = [i for i in hashes if i is not None]
        return hashes

    def get_hash(self, hash, csv_data) -> list:   

        alg = self.get_hash_algo(csv_data.get(hash.get("hash_alg")))
        content=csv_data.get(hash.get("hash_content"))
        hash_result = HashType(
                                alg=alg,
                                content=content
                            )
    
        return hash_result
    
    

    
    def get_licenses(self, licenses, csv_data) -> list:
        licenses = [self.get_license(license, csv_data) for license in licenses]
        licenses = [i for i in licenses if i is not None]
        return licenses 
    

    def get_licenses_from_api(self, licenses_from_api_) -> list:
        licenses_api = [self.get_license_from_api(license_api) for license_api in licenses_from_api_]
        licenses_api = [i for i in licenses_api if i is not None]
        return licenses_api 
    
    

    def get_exRefs(self, references, csv_data) ->list:
        exRefs = [self.get_exRef(reference, csv_data) for reference in references]
        exRefs = [i for i in exRefs if i is not None]
        return exRefs 
    
    
    def get_exRef(self, reference, csv_data) ->ExternalReference:
        type_ref = csv_data.get(reference.get("er_type"))
        url = csv_data.get(reference.get("er_url"))
        if type_ref is None:
            return None
        try:
            type_ref = ExternalReferenceType(type_ref)
        except:
            return None
        url = XsUri(url)
        exref_data = ExternalReference(
                                        type=type_ref, 
                                        url=url
                                    )
        return exref_data
    
     
    
    def build_contacts(self, name, email, phone) -> OrganizationalContact:
        try:
            contacts = OrganizationalContact(   name=name, 
                                                email=email, 
                                                phone=phone
                                            )
        except:

            #contacts = None
            pass
        return contacts

    def build_supplier(self, name, urls, contacts) -> OrganizationalEntity:
        try:
            supplier = OrganizationalEntity(
                                                name=name, 
                                                urls=urls, 
                                                contacts=contacts
                                            )
        except:

            #supplier = None
            pass
        return supplier
    

    
    def build_url(self, url) -> XsUri:
        s_url = None
        try:
            s_url = XsUri(url)
        except:
            s_url = None
        return s_url
    

    def cpe_wildcard(self, cpe :str):
        cpe = cpe.split(":")
        if "cpe" != cpe[0]:
            return None 
        cpe[-1] = "*:*:*:*:*:*"
        return ":".join(cpe) 
    
    
    def make_purl(self, package, name, version):
        if package == None:
            package = 'generic'
        name = name.replace(" ", "_")
        purl = "pkg:{}/{}@{}".format(package, name, version)
        purl_formatted  = PackageURL.from_string(purl)
        return purl_formatted
    

    def build_component(self, iteration:int, total:int, csv_data:pd.DataFrame, config_data:dict) -> Component:

        percentage = ((iteration + 1) / total * 100)
        print("\rGetting components-{}%".format(int(percentage)), sep=' ', end='', flush=True)
    
        name = config_data.get("name")
        version = config_data.get("version")
        # type = config_data.get("type")
        bom_ref = config_data.get("bom_ref")
        group = config_data.get("group")
        publisher = config_data.get("publisher")
        purl = config_data.get("purl")
        licenses = config_data.get("licenses")
        hashes = config_data.get("hashes")
        externalReferences = config_data.get("externalReferences")
        mime_type = config_data.get("mime_type")
        description = config_data.get("description")
        author = config_data.get("author")
        cpe = config_data.get("cpe")
        swid = config_data.get("swid")
        pedigree = config_data.get("pedigree")
        components = config_data.get("components")
        evidence = config_data.get("evidence")
        releaseNotes = config_data.get("releaseNotes")
        copyright = config_data.get("copyright")

        try:
            purl = PackageURL.from_string(csv_data.get(purl))
        except:
            purl=None

        if (purl is None) and (self.arg_data.get("add_purl") is True):
            purl = self.make_purl("generic", name, version)

        api_name = None
        api_version = None
        api_licenses = []
        
        if self.api is not None:
            api_package_data = self.api.search_package(purl)
            if api_package_data is not None:
                api_name = api_package_data.get("name")
                api_version = api_package_data.get("version")
                api_licenses = api_package_data.get("licenses")

            

        

        name = csv_data.get(name, api_name)
        if name is None:
            return None
        
        version = csv_data.get(version, api_version)
        # type = ComponentType(csv_data.get(type))
        bom_ref = csv_data.get(bom_ref)
        group = csv_data.get(group)
        publisher = csv_data.get(publisher)


        if licenses is not None and any(any(license.values()) for license in licenses):
            licenses = [lc_factory.make_from_string(lic) for lic in licenses]
        else:
            licenses = None


        if hashes is not None and any(any(hash.values()) for hash in hashes):
            hashes = self.get_hashes(hashes, csv_data)
        else:
            hashes = None
        
        
        if externalReferences is not None and any(any(externalreference.values()) for externalreference in externalReferences):
            externalReferences = self.get_exRefs(externalReferences, csv_data)
        else:
            externalReferences = None

        mime_type = csv_data.get(mime_type)
        description = csv_data.get(description)
        author = csv_data.get(author)
        cpe = csv_data.get(cpe)

        if (self.arg_data.get("cpe_wildcard") is True) and (cpe is not None):
            cpe = self.cpe_wildcard(cpe)
        
        swid = csv_data.get(swid)
        pedigree = csv_data.get(pedigree)
        components = csv_data.get(components)
        evidence = csv_data.get(evidence)
        releaseNotes = csv_data.get(releaseNotes)
        copyright = csv_data.get(copyright)


        sbom_component = Component(   
                                        name = name,
                                        version = version,
                                        # type = type,
                                        bom_ref = bom_ref,
                                        group = group,
                                        publisher = publisher,
                                        purl = purl,
                                        licenses = licenses,
                                        hashes = hashes,
                                        external_references = externalReferences,
                                        mime_type = mime_type,
                                        description = description,
                                        author = author,
                                        cpe = cpe,
                                        swid = swid,
                                        pedigree = pedigree,
                                        components = components,
                                        evidence = evidence,
                                        release_notes = releaseNotes,
                                        copyright = copyright,

                                    )
        
        return sbom_component

            
    def assemble_components(self, csv_data, config_data) -> list:
        config_data=config_data.get("component_configuration")
        total = len(csv_data)
        try:
            print("Getting components...", end="")
            components = [self.build_component(i, total, x, config_data) for i, x in csv_data.iterrows()]
            print("\r")
            return components
        except Exception as err:
            print(err)
            exit(0)


    def create_metadata(self, setup_data:dict):

        print("Getting metadata...")
        metadata_manufacture = None
        metadata_component = None
        metadata_supplier = None

        try:
            if  setup_data.get("manufacturer_name") is not None:
                metadata_manufacture = OrganizationalEntity(
                                                            name= setup_data.get("manufacturer_name"),
                                                            urls=  setup_data.get("manufacturer_url"), 
                                                            contacts=  setup_data.get("manufacturer_contact")
                                                       )
        except:
            #metadata_manufacture = None
            pass

        try:    
            if  setup_data.get("supplier_name") is not None:
                metadata_supplier = OrganizationalEntity(
                                                            name= setup_data.get("supplier_name"),
                                                            urls=  setup_data.get("supplier_url"), 
                                                            contacts=  setup_data.get("supplier_contact")
                                                        )
            else:
                metadata_supplier = None  
        except:
            #metadata_supplier = None
            pass
            

        metadata_component = Component(
                                        name=setup_data.get("sbom_name"), 
                                        version=setup_data.get("sbom_version"),
                                        type=ComponentType(setup_data.get("sbom_type")),
                                        namespace= setup_data.get("namespace"),
                                        purl=self.make_purl(setup_data.get("package_type"), setup_data.get("sbom_name"),setup_data.get("sbom_version")),

                                    )
        #metadata_component = None

        return  metadata_component,metadata_manufacture, metadata_supplier
    

        
    
    
    def build_sbom(self):
        print("Assembling SBOM...")
        metadata_component,metadata_manufacture, metadata_supplier = self.create_metadata(self.arg_data)
        metadata = BomMetaData(
                                component=metadata_component,
                                manufacture=metadata_manufacture,
                                supplier=metadata_supplier

                            )
        components=self.assemble_components(self.csv_data, self.json_data)
        components = [i for i in components if i is not None]
        

        bom = Bom(
                    components=components,
                    metadata=metadata,
            )
        
        bom.register_dependency(metadata_component, components)
        outputter: BaseOutput = get_instance(bom=bom, output_format=OutputFormat.JSON)
        print("SBOM assembled, outputting to {}".format(self.output_file))
        #outputter.output_to_file(self.output_file)
        try:
            outputter.output_to_file(self.output_file)
        except FileExistsError:
            answer = input("This sbom file already exists. do you want to overwrite? (Y/N):   ")
            if answer == ("y" or "Y"):
                print("Overwriting file...")
                os.remove(self.output_file)
                outputter.output_to_file(self.output_file)
            else:
                print("OK then")
        print("Finished. Have a nice day!")
