import pandas as pd
import json
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import ComponentType, Component
from cyclonedx.model import OrganizationalEntity, OrganizationalContact, XsUri
from cyclonedx.model import HashAlgorithm, HashType, License, LicenseChoice, ExternalReference, ExternalReferenceType
from cyclonedx.output import get_instance, BaseOutput, OutputFormat
from packageurl import PackageURL
from pathlib import Path
from time import sleep
import os
import warnings
warnings.filterwarnings("ignore", message="The Component this BOM is describing None has no defined dependencies which means the Dependency Graph is incomplete - you should add direct dependencies to this Componentto complete the Dependency Graph data.")




class Builder2:
    def __init__(self, arg_data: dict,  csv_data :pd.DataFrame, json_data :dict):

        self.arg_data = arg_data
        self.csv_data = csv_data
        self.json_data = json_data
        self.ouput_file = Path(self.arg_data.get("file"),"").stem + "_sbom.json"


    def get_hash_algo(self, algorithm):
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
    

    def get_license(self, license, csv_data):
        url =csv_data.get(license.get("license_url"))
        id=csv_data.get(license.get("license_id"))
        name=csv_data.get(license.get("license_name"))
        if url is not None:
            url = XsUri(url)
        if (name is None) and (id is None):
            return
        
        license = License(  
                            url=url,
                            name=name,
                            id=id
                        )
        license_choice = LicenseChoice( 
                                        license=license
                                    )
        return license_choice

    def get_exRefs(self, references, csv_data) ->list:
        exRefs = [self.get_exRef(reference, csv_data) for reference in references]
        exRefs = [i for i in exRefs if i is not None]
        return exRefs 
    
    
    def get_exRef(self, reference, csv_data) ->ExternalReference:
        type_ref = csv_data.get(reference.get("er_type"))
        url = csv_data.get(reference.get("er_url"))
        if type_ref is None:
            return None
        type_ref = ExternalReferenceType(type_ref)
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
    

    def build_component(self, iteration:int, total:int, csv_data:pd.DataFrame, config_data:dict) -> Component:

        percentage = ((iteration + 1) / total * 100)
        print("\rgetting components-{}%".format(int(percentage)), sep=' ', end='', flush=True)
    
        name = config_data.get("name")
        version = config_data.get("version")
        type = config_data.get("type")
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

        name = csv_data.get(name)
        version = csv_data.get(version)
        type = ComponentType(csv_data.get(type))
        bom_ref = csv_data.get(bom_ref)
        group = csv_data.get(group)
        publisher = csv_data.get(publisher)


        purl = PackageURL.from_string(csv_data.get(purl))


        licenses = self.get_licenses(licenses, csv_data)
        hashes = self.get_hashes(hashes, csv_data)
        externalReferences = self.get_exRefs(externalReferences, csv_data)

        mime_type = csv_data.get(mime_type)
        description = csv_data.get(description)
        author = csv_data.get(author)
        cpe = csv_data.get(cpe)
        swid = csv_data.get(swid)
        pedigree = csv_data.get(pedigree)
        components = csv_data.get(components)
        evidence = csv_data.get(evidence)
        releaseNotes = csv_data.get(releaseNotes)
        copyright = csv_data.get(copyright)


        sbom_component = Component(   
                                        name = name,
                                        version = version,
                                        type = type,
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
            print("getting components...", end="")
            components = [self.build_component(i, total, x, config_data) for i, x in csv_data.iterrows()]
            print("\r")
            return components
        except Exception as err:
            print(err)
            exit(0)


    def create_metadata(self, setup_data:dict):

        print("getting metadata")
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
        print("assembling sbom...")
        metadata_component,metadata_manufacture, metadata_supplier = self.create_metadata(self.arg_data)
        metadata = BomMetaData(
                                component=metadata_component,
                                manufacture=metadata_manufacture,
                                supplier=metadata_supplier

                            )
        components=self.assemble_components(self.csv_data, self.json_data)
        

        bom = Bom(
                    components=components,
                    metadata=metadata
            )
        outputter: BaseOutput = get_instance(bom=bom, output_format=OutputFormat.JSON)
        print("sbom assembled, outputting to {}".format(self.ouput_file))
        #outputter.output_to_file(self.ouput_file)
        try:
            outputter.output_to_file(self.ouput_file)
        except FileExistsError:
            answer = input("this sbom file already exists. do you want to overwrite? (Y/N):   ")
            if answer == ("y" or "Y"):
                print("overwriting file...")
                os.remove(self.ouput_file)
                outputter.output_to_file(self.ouput_file)
            else:
                print("ok then")
        print("finished. have a nice day!")
