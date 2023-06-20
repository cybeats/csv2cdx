import csv2cdx
from .parse import Parser
from .build import Builder2

def main():
    parser = Parser()

    args, data, config = parser.get_data()

    builder = Builder2(args, data, config)

    builder.build_sbom()

if __name__ == "__main__":
    main()
