from importlib.metadata import version

try:
    __version__ = version("csv2cdx")
except:
    __version__ = "dev"