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
from pathlib import Path
import argparse




class Parser:

    #def __init__(self, excel_file:str, json_file:str) -> None:
    def __init__(self) -> None:
        self.csv_data = {}
        self.json_data = {}
        self.arg_data = {}

    def get_args(self) -> dict:

        parser = argparse.ArgumentParser(description="csv2cdx")

        #required arguements
        parser.add_argument("-c", type=str, required=True, help="json configuration file")
        parser.add_argument("-f", type=str, required=True, help="excel file")
        parser.add_argument("-pt", type=str, required=True, help="package type")
        parser.add_argument("-t", type=str, required=True, help="sbom type")
        parser.add_argument("-pn", type=str, required=True, help="sbom component name")
        parser.add_argument("-pv", type=str, required=True, help="sbom component version")

        #optional arguements
        parser.add_argument("-mn", type=str, required=False, help="manufacturer name (optional)", default=None)
        parser.add_argument("-sn", type=str, required=False, help="supplier name (optional)", default=None)
        parser.add_argument("-ns", type=str, required=False, help="namespace (optional)", default=None)
        parser.add_argument("-cw", type=bool, required=False, help="cpe wildcard (optional)" , default=None)
        parser.add_argument("-ap", type=bool, required=False, help="add purl (optional)", default=False)
        parser.add_argument("-cnt", type=bool, required=False, help="csv no title (optional)", default=False)
        parser.add_argument("-api", type=bool, required=False, help="utilize cybeats api(optional)", default=False)
        parser.add_argument("-url", type=str, required=False, help="cybeats api url(optional)", default=None)
        parser.add_argument("-ak", type=str, required=False, help="cybeats access key(optional)", default=None)
        parser.add_argument("-sk", type=str, required=False, help="cybeats secret key(optional)", default=None)

        args=parser.parse_args()
    
        parameters = {}

        #required parameters
        try:
            parameters["json"] = args.c 
            parameters["file"] = args.f
            parameters["package_type"] = args.pt
            parameters["sbom_type"] = args.t
            parameters["sbom_name"] = args.pn
            parameters["sbom_version"] = args.pv
        except Exception as err:
            print(err)
            print("Exiting...")
            exit(0)

        #optional parameters
        try:
            parameters["manufacturer_name"] = args.mn
            parameters["supplier_name"] = args.sn
            parameters["namespace"] = args.ns
            parameters["cpe_wildcard"] = args.cw
            parameters["add_purl"] = args.ap
            parameters["csv_no_title"] = args.cnt
            parameters["use_api"] = args.api
            parameters["api_url"] = args.url
            parameters["access_key"] = args.ak
            parameters["secret_key"] = args.sk


        except Exception as err:
            print(err)
            print("Exiting...")
            exit(0)

        return parameters


    #check is input file is .csv or .xlsx
    def parse_csv(self,file, header) -> pd.DataFrame:
        file_extension = Path(file).suffix
        file_data = None

        print("Loading {filename}...".format(filename=file))

        if file_extension == ".xlsx":
            file_data = pd.read_excel(file, header=header)
        
        elif file_extension == ".csv":
            file_data = pd.read_csv(file, header=header)
        
        else:
            print("Invalid data file, exiting...\n")
            exit(0)

        file_data = file_data.where(pd.notnull(file_data), None)
        print("CSV {filename} loaded".format(filename=file))
        return file_data


    #reads csv
    def read_csv(self, file) -> pd.DataFrame: 

        if self.arg_data.get("csv_no_title") is True:
            csv_df = self.parse_csv(file, header=None)
            index = [x for x in range(len(csv_df.columns))]
            print("No column names, assigning headers based on column index")
            csv_df.columns = index
        
        else:
            csv_df = self.parse_csv(file, header=0) 
        
        #data = csv_df.to_dict('index')
        return csv_df
    
    #reads json
    def read_json(self, file) -> dict: 
        data = {}
        with open(file, "r") as jd: 
            data = json.load(jd)
        print("JSON {filename} loaded".format(filename=file))
        return data
    
        
    #gets all arguement, csv and json data
    def get_data(self) -> dict:
        self.arg_data = self.get_args()
        self.csv_data = self.read_csv(self.arg_data.get("file"))
        self.json_data = self.read_json(self.arg_data.get("json"))

        return self.arg_data, self.csv_data, self.json_data

                                                                                                                                                                                                                                                                                                                                                                                                      


