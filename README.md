### Introduction

---

This application enables you to capture legacy information about open-source software components contained in an Excel file and have that information converted into a Software Bill of Materials (SBOMs) file in JSON that conforms to the [CycloneDX standard](https://cyclonedx.org/docs/1.4/json/).

### Installation

---

In order to install csv2cdx the following prerequisites are required:

* Git
* Python3
* Pip

Clone the repository to your local branch via the command:

`git clone https://github.com/cybeats/csv2cdx.git`

Then, install the requirements via:

`pip install  -r requirements.txt`

### Usage

---

To use the csv2cdx tool you will require 3 things:

* The csv2cdx application itself
* A .csv/.xlsx data file
* A .json configuration file

#### Configuration File

---

The .json configuration file is neccessary to translate the headers (or indexes) of your .csv file to representations the csv2cdx program will be compatible with. Its basic layout, without any populated headers is as follows:

```json
{
  "component_configuration": {
    "name": null,
    "version": null,
    "type": null,
    "bom-ref": null,
    "group": null,
    "publisher": null,
    "purl": null,
    "licenses": [
      {
        "license_name": null,
        "license_url": null,
        "license_id": null
      }
    ],
    "hashes": [
      {
        "hash_alg": null,
        "hash_content": null
      }
    ],
    "externalReferences": [
      {
        "er_type": null,
        "er_url": null
      }
    ],
    "mime type": null,
    "description": null,
    "author": null,
    "cpe": null,
    "swid": null,
    "pedigree": null,
    "components": null,
    "evidence": null,
    "releaseNotes": null,
    "copyright": null
  }
}
```

You can populate this json by adding the name of the column to the corresponding parameter e.g:

```json
"name": "Component_Name",
"version": "component_version",
"type": "comp_type",
```

Note: "type" object MUST be one of the types inherent to the [CycloneDX json format](https://cyclonedx.org/docs/1.4/json/#metadata_component_type)

For array fields such as licenses, hashes and external references, the requisite json object can be duplicated for every occurence e.g:

```json
"licenses": [
      {
        "license_name": "license_1",
        "license_url": "license_url_1",
        "license_id": "license_id_1"
      },    {
        "license_name": "license_2",
        "license_url": "license_url_2",
        "license_id": "license_id_2"
      },    {
        "license_name": "license_3",
        "license_url": "license_url_3",
        "license_id": "license_id_3"
      }
    ]
```

#### Command Parameters

---

The basic command format to create a sbom json is the following:

```bash
python3 csv2cdx.py -f (csv file path) -c (configuration json file path) -pn (name of sbom)  -pv (sbom version) -t (sbom type) -pt (sbom package type)
```

This command utilizes all neccessary flags:

* -f : "file". Adds the .csv data file path e.g. example_data.csv
* -c : "config". Adds the .json configuration file path e.g. example_config.csv
* -pn : "sbom name". Adds the sbom's name e.g. example_sbom
* -pv : "sbom version". Adds the sbom's version e.g. 1.0.0
* -t : "type". Adds the sbom's type (application, framework, library, container, operating-system, device, firmware, file) as shown by the [CycloneDX json format](https://cyclonedx.org/docs/1.4/json/#metadata_component_type)
* -pt :"package type".  Adds the sbom's package type (e.g. pypi, maven, cargo, etc). Default/no package should be given the field "generic"

Additionally there are optional flags for additional configuration:

* -mn : "manufacturer name". Adds the manufacturer name for the component the sbom describes
* -sn : "supplier name". Adds the name of the supplier for the component the sbom describes
* -ns : "namespace". Adds the namespace of the component the sbom descibes
* -cw : "cpe wildcard". Making this flag "true" wildcards any cpe in the sbom components e.g. `cpe:2.3:a:microsoft:internet_explorer:8.0` to `cpe:2.3:a:microsoft:internet_explorer:*`. (wildcarded version)
* -ap : "add purl". Making this flag "true" adds PURLs to the components of the sboms. This is to be used if they do not already exist in the .csv file.
* -cnt : "csv no title". Making this flag "true" indexes the .csv file by column number instead of name. As such, the configuration json format should look like:

  ```json
  "name": 0,
  "version": 1,
  "type": 2,
  ```

#### Output

---

the result should be a .json file in your current directory with the filename (name of your .csv file).json.


### Feedback

---

Please email [cs@cybeats.com](mailto:cs@cybeats.com)
