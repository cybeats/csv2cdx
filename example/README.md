# Example

This folder contains an example data.csv data file and example_config.json configuration file.

The csv file contains synthetic data containing component :

* names
* versions
* hashes
* descriptions

A resulting sbom json file can be made by running the command

```bash
csv2cdx -pn <binary-name> -pv 1.0.0 -t application -c example_config.json -f <csv-file-name>.csv -pt generic 
```
