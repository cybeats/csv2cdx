import pandas as pd
import json
from pathlib import Path



class Parser:

    #def __init__(self, excel_file:str, json_file:str) -> None:
    def __init__(self, args) -> None:
        self.csv_data = {}
        self.json_data = {}
        self.arg_data = {}
        self.args = args

    def get_args(self, args) -> dict:
   
        parameters = {}

        #required parameters
        try:
            parameters["json"] = args.get("c") 
            parameters["file"] = args.get("f")
            parameters["package_type"] = args.get("pt")
            parameters["sbom_type"] = args.get("t")
            parameters["sbom_name"] = args.get("pn")
            parameters["sbom_version"] = args.get("pv")
        except Exception as err:
            print(err)
            print("Exiting...")
            exit(0)

        #optional parameters
        try:
            parameters["manufacturer_name"] = args.get("mn")
            parameters["supplier_name"] = args.get("sn")
            parameters["namespace"] = args.get("ns")
            parameters["cpe_wildcard"] = args.get("cw")
            parameters["add_purl"] = args.get("ap")
            parameters["csv_no_title"] = args.get("cnt")
            parameters["use_api"] = args.get("api")
            parameters["api_url"] = args.get("url")
            parameters["access_key"] = args.get("ak")
            parameters["secret_key"] = args.get("sk")
            parameters["parse_compound"] = args.get("pvc")
            parameters["format"] = args.get("format")


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
        self.arg_data = self.get_args(self.args)
        self.csv_data = self.read_csv(self.arg_data.get("file"))
        self.json_data = self.read_json(self.arg_data.get("json"))

        return self.arg_data, self.csv_data, self.json_data

                                                                                                                                                                                                                                                                                                                                                                                                      