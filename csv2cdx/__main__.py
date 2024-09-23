from .template import create_template_file
from .parse import Parser
from .build import Builder
import argparse
import csv2cdx

def main():
    parser = argparse.ArgumentParser(description=f"csv2cdx v{csv2cdx.__version__}")
    subparsers = parser.add_subparsers(dest='subcommand', required=False)

    template = subparsers.add_parser("template", help="Generates json configuration template file. Run csv2cdx template -h for more details")
    template.add_argument("-name", type=str, required=False, help="Json configuration file name. Default: config_template.")

    build = subparsers.add_parser("build", help="Build sbom given args. Run csv2cdx build -h for more details")

    #required arguments
    build.add_argument("-c", type=str, required=True, help="json configuration file")
    build.add_argument("-f", type=str, required=True, help="excel file")
    build.add_argument("-pt", type=str, required=True, help="package type")
    build.add_argument("-t", type=str, required=True, help="sbom type")
    build.add_argument("-pn", type=str, required=True, help="sbom component name")
    build.add_argument("-pv", type=str, required=True, help="sbom component version")

    #optional arguments
    build.add_argument("-mn", type=str, required=False, help="manufacturer name (optional)", default=None)
    build.add_argument("-sn", type=str, required=False, help="supplier name (optional)", default=None)
    build.add_argument("-ns", type=str, required=False, help="namespace (optional)", default=None)
    build.add_argument("-cw", type=bool, required=False, help="cpe wildcard (optional)" , default=None)
    build.add_argument("-ap", type=bool, required=False, help="add purl (optional)", default=False)
    build.add_argument("-cnt", type=bool, required=False, help="csv no title (optional)", default=False)
    build.add_argument("-api", type=bool, required=False, help="utilize cybeats api(optional)", default=False)
    build.add_argument("-url", type=str, required=False, help="cybeats api url(optional)", default=None)
    build.add_argument("-ak", type=str, required=False, help="cybeats access key(optional)", default=None)
    build.add_argument("-sk", type=str, required=False, help="cybeats secret key(optional)", default=None)
    build.add_argument("-pvc", type=bool, required=False, help="parse compound version", default=False)
    build.add_argument("-format", type=str, required=False, help="sbom format [json, xml], default json", default="json")


    args = parser.parse_args()
    values = vars(args)

    subcommand = values.get("subcommand")

    if subcommand == "template":
        filename = values.get("name")
        print("creating template file")
        create_template_file(filename)
        exit(0)

    elif subcommand == "build":
        parser = Parser(values)
        args, data, config = parser.get_data()
        builder = Builder(args, data, config)
        builder.build_sbom()


if __name__ == "__main__":
    main()