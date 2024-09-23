import time
import hashlib
import hmac
import base64
import json
import requests
from packageurl import PackageURL


class cybeats_API():
    def __init__(self, api_url, access_key, secret_key, package_type) -> None:
        
        self.access_key = access_key
        self.secret_key = secret_key
        self.cybeats_url = api_url + "/v1/sboms/componentcatalog/packages"

        self.package_type = package_type

        self.have_data = False

        self.package_data = self.get_package_data(package_type)
    

    def calculate_vsig(self,timestamp, body):
        secretAccessKey = bytes(self.secret_key, 'utf-8')
        data = bytes((str(timestamp)+json.dumps(body, separators=(',', ':'))), 'utf-8')
        data_hmac = hmac.new(secretAccessKey, data, hashlib.sha256)
        vsig = base64.urlsafe_b64encode(data_hmac.digest()).decode('utf-8').replace("=", "")
        return vsig
    
    def build_headers(self, timestamp, body):
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "x-fwup-access-key-id": self.access_key,
            "x-fwup-dtstmp": str(timestamp),
            "x-fwup-vsig": self.calculate_vsig(timestamp, body)
        }
        return headers
    
    def get_software_catalog(self, pkgtype):
        timestamp = int(time.time())
        body = {"pkgType":pkgtype}
        response = requests.post(self.cybeats_url , headers=self.build_headers(timestamp, body), data=json.dumps(body, separators=(',', ':')))
        code = response.status_code
        text = json.loads(response.text)
        return code, text
    
    
    def get_package_data(self, pckg_type):
        ret_code, ret_data = self.get_software_catalog(pckg_type)
        if ret_code !=200:
            self.have_data = False
            return -1
        data_list = ret_data["entities"][0].get("components")
        data_dict = {PackageURL.from_string(package.get("purl")):package  for package in data_list if package.get("purl") is not None and package.get("purl").count(":") < 2}
        self.have_data = True
        return data_dict
    
    def search_package(self, purl_arg):
        if(type(purl_arg)) != PackageURL:
            return None
        if(self.have_data):
            return self.package_data.get(purl_arg)
        else:
            return None





