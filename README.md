# README

This README would normally document whatever steps are necessary to get your application up and running.

### About the csv2cdx Tool

This application enables you to capture legacy information about open-source software components contained in an Excel file and have that information converted into a Software Bills of Materials (SBOMs) file in JSON that conforms to the CycloneDX standard.

The resulting SBOM file can be uploaded into SBOM Studio for analysis.

### Requirements for Using This Application

Pandas library for Python
cyclonedx-python-lib
JSON configuration file
Source files in Excel (.xls, .xlsx, .csv)

### Getting Started with csv2cdx Tool

1. Clone the repository **csv2cdx** from the command line interface or terminal application
2. Enter the project folder **csv2cdx**
3. Execute the application by typing **python3 csv2cdx.py**
4. To select options for the SBOM, set the following required flags:
   * To customize the JSON Configuration File that will map columns from your Excel file, set the flag -ct
   * To set the path to your source Excel file, set the flag -f
   * To set the package type that your overall SBOM component uses, set the flag -pt
   * To set the type of overall type of component that the SBOM describes, set the flag -t
   * To give a version number to the overall SBOM component, set the flag -pv
5. In addition, the following optional flags provide additional data for the output file:
   * To enter the name of the manufacturer of the overall SBOM component, set the flag -mn
   * To enter the name of the supplier of the overall SBOM component, set flag -sn
   * To give the overall SBOM component a namespace, set flag -ns
   * To make the CPE a wildcard, set flag -cw
   * To have the tool create a PURL if one does not already exist, set flag -ap
   * To instruct the tool to read a .csv file using column numbers instead of column names, set flag -cnt
6. After setting the flags, the tool will save the output JSON file containing the SBOM information to the project folder

### Where to Get Support

cs@cybeats.com
