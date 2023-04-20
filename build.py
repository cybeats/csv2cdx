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
        hash_list = []
        try:
            for hash in hashes:
                alg = self.get_hash_algo(csv_data.get(hash.get("hash_alg", None)))
                hash_result = HashType(
                                        alg=alg,
                                        content=csv_data(hash.get("hash_content", None))
                                    )
            hash_list.append(hash_result)
        except:
            #hash_list = None
            pass
        return hash_list
    
    

    
    def get_licenses(self, licenses, csv_data) -> list:
        license_list = []
        try:
            for license in licenses:
                url = self.build_url(csv_data.get(license.get("license_url")))
                id=csv_data.get(license.get("license_id"))
                name=csv_data.get(license.get("license_name"))
                lic_obj = License(
                                    id=id, 
                                    name=name, 
                                    url=url
                                )

                lic = LicenseChoice(license=lic_obj)
                license_list.append()
        except:
            #license_list = None
            pass
        return license_list
    

    def get_exRef(self, references, csv_data) ->list:
        exref_list = []
        try:
            for exref in exref_list:
                type = ExternalReferenceType(csv_data.get(exref.get("er_type")))
                url = self.build_url(csv_data(exref.get("er_url")))
                exref_data = ExternalReference(
                                                type=type, 
                                                url=url
                                            )
                
                exref_list.append(exref_data)
        except:
            #exref_list = None
            pass
        return exref_list

     
    
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
        try:
            s_url = XsUri(url)
        except:

            #s_url = None
            pass
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
        #print("\rassembling components-{}%".format(int(percentage)), sep=' ', end='', flush=True)
        
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
        #purl=csv_data.get(purl)
        licenses = self.get_licenses(licenses, csv_data)
        

        hashes = self.get_hashes(hashes, csv_data)

        externalReferences = self.get_exRef(externalReferences, csv_data)

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
            print("assembling components...", end="")
            components = [self.build_component(i, total, x, config_data) for i, x in csv_data.iterrows()]
            print("\n\rcomponents assembled")
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
                                        type=ComponentType( setup_data.get("sbom_type")),
                                        namespace= setup_data.get("namespace")                                                                               
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
        bom_json: str = outputter.output_as_string()
        outputter.output_to_file(self.ouput_file)
        print(bom_json)







    





    


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
  


