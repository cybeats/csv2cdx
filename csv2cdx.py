from parse import Parser
from build import Builder2


if __name__ == "__main__":
    parser = Parser()

    args, data, config = parser.get_data()

    builder = Builder2(args, data, config)

    builder.build_sbom()





