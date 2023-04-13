import argparse
import os
import json
import parsing
from parsing import Parser, Builder



parser = argparse.ArgumentParser(description="CSV2CDX")

parser.add_argument("-c", type=str, required=True, help="JSON Configuration File")
parser.add_argument("-f", type=str, required=True, help="Excel File")

parser.add_argument("-pt", type=str, required=True, help="Package Type")

parser.add_argument("-t", type=str, required=True, help="SBOM type")

parser.add_argument("-pn", type=str, required=True, help="SBOM Component Name")

parser.add_argument("-pv", type=str, required=True, help="SBOM Component Version")

parser.add_argument("-mn", type=str, required=False, help="Manufacturer Name")

parser.add_argument("-sn", type=str, required=False, help="Supplier Name")

parser.add_argument("-ns", type=str, required=False, help="Namespace")

parser.add_argument("-cw", type=str, required=False, help="CPE Wildcard")

parser.add_argument("-ap", type=bool, required=False, help="Add PURL")

parser.add_argument("-cnt", type=bool, required=False, default=True, help="CSV No Title")

args=parser.parse_args()

config_file = args.c 
data_file = args.f 


config_parse = parsing.Parser(data_file, config_file)


j_dict = config_parse.read_json()
# csv_dict = config_parse.read_excel()


j_dict["sbom_component_name"] = args.pn
j_dict["sbom_component_version"] = args.pv
j_dict["sbom_type"] = args.t
j_dict["package_type"] = args.pt

if args.ns:
    j_dict["namespace"] = args.ns
if args.cw:
    j_dict["wildcard"] = args.cw
if args.mn:
    j_dict["manufacturer_name"] = args.mn
if args.sn:
    j_dict["supplier_name"] = args.sn
if args.cnt:
    j_dict["csv_no_title"] = args.cnt
if args.ap:
    j_dict["add_purl"] = args.ap

csv_dict = config_parse.read_excel()

build= parsing.Builder(csv_dict, j_dict)
build.create_sbom()



