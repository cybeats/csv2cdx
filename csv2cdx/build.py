import pandas as pd
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import ComponentType, Component
from cyclonedx.model import XsUri
from cyclonedx.model import HashAlgorithm, HashType, ExternalReference, ExternalReferenceType, Tool
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model.license import LicenseExpression
from packageurl import PackageURL
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.output import make_outputter, BaseOutput
from pathlib import Path
from .cy_api import cybeats_API
from .template import configs
import csv2cdx

lc_factory = LicenseFactory()

class Builder:
    def __init__(self, arg_data: dict,  csv_data :pd.DataFrame, json_data :dict):

        self.arg_data = arg_data
        self.csv_data = csv_data
        self.json_data = json_data
        self.use_api = self.arg_data.get("use_api")
        self.api = self.api_url = self.api_access_key = self.api_secret_key = None
        if self.use_api:
            self.api_url = self.arg_data.get("api_url")
            self.api_access_key = self.arg_data.get("access_key")
            self.api_secret_key = self.arg_data.get("secret_key")
            if self.api_url and self.api_access_key and self.api_secret_key:
                self.api = cybeats_API(api_url=self.api_url, access_key=self.api_access_key, secret_key=self.api_secret_key, package_type=arg_data.get("package_type"))
            else:
                print("Missing api credentials, defaulting to local assembly")
                self.use_api = False
                self.api = self.api_url = self.api_access_key = self.api_secret_key = None
        else:
            self.api = self.api_url = self.api_access_key = self.api_secret_key = None

        self.file = arg_data.get("file")
        self.filename = Path(self.file).stem
        self.format = arg_data.get("format", "json")
        self.output_format = {"xml":OutputFormat.XML, "json": OutputFormat.JSON}.get(self.format, OutputFormat.JSON)
        self.output_file = f"{self.filename}_sbom.{self.format}"

        self.bom = Bom()
        self.add_purl = self.arg_data.get("add_purl")
        self.cpe_wildcard = self.arg_data.get("cpe_wildcard")
        self.parse_compound = self.arg_data.get("parse_compound")

        self.csv_length = len(csv_data)
        self.iteration = 0


    def get_val(self, keyword:str, csv_data:pd.Series, config_data:dict) -> str | None:
            res = None
            key = config_data.get(keyword)
            if key is None:
                return res
            if type(key) is str:
                res = csv_data.get(key)
            return res
    
    def get_licenses(self, license_config, csv_data) -> list:
        licenses = []
        for lic in license_config.get('licenses'):

            x = [self.get_val(i, csv_data, lic) for i in lic.keys()]
            if (any(lic.values())) and (any(x)) and (x[0]):
                licenses.append(lc_factory.make_from_string(
                                                                value=self.get_val('license_name', csv_data, lic)
                                                            )
                                                        ) 
            else:
                 continue

        licenses = [x for x in licenses if x is not None]

        return licenses
    
    def get_hashes(self, hashes_config, csv_data) -> list:
        hashes = []
        
        for hash in hashes_config.get('hashes'):

            if not any(hash.values()):
                continue
            x = [self.get_val(i, csv_data, hash) for i in hash.keys()]
            if all(hash.values()) and all(x):
                hashes.append(
                                HashType(
                                            alg=HashAlgorithm(self.get_val('hash_alg', csv_data, hash)),
                                            content= self.get_val('hash_content', csv_data, hash)
                                        )
                            ) 
            else:
                 continue
        hashes = [x for x in hashes if x is not None]
        return hashes
    
    def get_exrefs(self, exref_config, csv_data) -> list:
        exrefs = []
        
        for exref in exref_config.get('externalReferences'):

            type = self.get_val('er_type', csv_data, exref)
            url =  self.get_val('er_url', csv_data, exref)
            if (all(exref.values())) and (all([type, url])):
                exrefs.append(
                                ExternalReference(
                                                    type=ExternalReferenceType(type),
                                                    url=XsUri(url)

                                                )
                            )
            else:
                 continue 
        exrefs = [x for x in exrefs if x is not None]
        return exrefs
        
    def get_component(self, csv_data:pd.Series, config_data:dict) -> Component:
            component = Component(name='name')
            for key in configs.keys():
                if hasattr(component, key) and type(key) is str: 
                    res = self.get_val(key, csv_data, config_data)
                    setattr(component, key, res)

            res = self.get_val('purl', csv_data, config_data)
            if res:
                setattr(component, 'purl', PackageURL.from_string(res))

            if self.add_purl:
                purl = PackageURL(type=self.arg_data.get('package_type'), name=component.name.replace(" ", "-"), version=component.version)
                setattr(component, 'purl', purl)                                          
                
            licenses = self.get_licenses(config_data, csv_data)
            setattr(component, 'licenses', licenses)

            hashes = self.get_hashes(config_data, csv_data) 
            setattr(component, 'hashes', hashes)

            exrefs = self.get_exrefs(config_data, csv_data)
            setattr(component, 'external_references', exrefs)

            if self.parse_compound:
                name_ver = self.get_val('name', csv_data, config_data).split(" ")
                new_version = name_ver[-1].strip()
                new_name = " ".join(name_ver[:-1]).strip()
                component.name = new_name
                component.version = new_version

            if self.use_api and component.purl:
                    api_package_data = self.api.search_package(component.purl)
                    if api_package_data:
                        component.name = api_package_data.get("name")
                        component.version = api_package_data.get("version")
                        component.licenses = [lc_factory.make_from_string(i.get('id' if 'id' in i.keys() else 'name')) for i in api_package_data.get("licenses")]
            
            if self.cpe_wildcard and component.cpe:
                 cpe_wc = component.cpe.split(":")
                 cpe_wc[-1] = "*:*:*:*:*:*"
                 cpe_wc = ":".join(cpe_wc)
                 component.cpe = cpe_wc
            
            return component

    def assemble_components(self, csv_data, config_data) -> list:
            try:
                print("Getting components...", end="")
                components = [self.get_component(x, config_data) for i, x in csv_data.iterrows()]
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
                pass

            metadata_component = Component(
                                            name=setup_data.get("sbom_name"), 
                                            version=setup_data.get("sbom_version"),
                                            type=ComponentType(setup_data.get("sbom_type")),
                                            purl=PackageURL(setup_data.get("package_type"), setup_data.get("sbom_name"),setup_data.get("sbom_version")),
                                        )

            return  metadata_component,metadata_manufacture, metadata_supplier
    
    def build_sbom(self):
            print("Assembling SBOM...")
            metadata_component,metadata_manufacture, metadata_supplier = self.create_metadata(self.arg_data)

            metadata = BomMetaData(
                                    component=metadata_component,
                                    manufacture=metadata_manufacture,
                                    supplier=metadata_supplier

                                )
            metadata.tools.add(
                                Tool(
                                        name="csv2cdx",
                                        version=csv2cdx.__version__,
                                        vendor="Cybeats Technologies",
                                        external_references=[
                                            ExternalReference(
                                                type=ExternalReferenceType.VCS,
                                                url=XsUri('https://github.com/cybeats/csv2cdx')
                                            ),

                                            ExternalReference(
                                                type=ExternalReferenceType.WEBSITE,
                                                url=XsUri('https://github.com/cybeats/csv2cdx/#readme')
                                            )

                                        ]
                                    )
                            )
            
            components=self.assemble_components(self.csv_data, self.json_data)
            components = [i for i in components if i is not None]
            

            bom = Bom(
                        components=components,
                        metadata=metadata 
                    )
            
            bom.register_dependency(metadata_component, components)

            out:BaseOutput = make_outputter(
                                                bom=bom, 
                                                output_format=self.output_format, 
                                                schema_version=SchemaVersion.V1_5
                                            )
            
            
            print(f"SBOM assembled, outputting to {self.output_file} file")
            
            if Path(self.output_file).is_file():
                res = input("File already exists. Overwrite? (Y/N): ")
                if res.lower() != 'y':
                    print("Exiting...")
                    exit(0)

            out.output_to_file(
                                filename=self.output_file, 
                                allow_overwrite=True, 
                                indent=4
                            )
      