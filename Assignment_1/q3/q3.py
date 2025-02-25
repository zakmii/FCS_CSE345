import json
import subprocess
import pandas as pd
from abc import ABC, abstractmethod

class IPResolverStrategy(ABC):
    """Abstract base class for IP resolution strategies."""
    @abstractmethod
    def get_ip_address(self, subdomain: str) -> str:
        pass

class NSLookupResolver(IPResolverStrategy):
    """IP Resolver using nslookup."""
    def get_ip_address(self, subdomain: str) -> str:
        try:
            result = subprocess.run(["nslookup", subdomain], capture_output=True, text=True)
            output = result.stdout

            lines = output.split("\n")
            addresses = []

            for line in lines:
                if "Address" in line and not line.startswith("Server"):
                    addresses.append(line.split(":")[-1].strip())

            if len(addresses) > 1:
                return addresses[1]  
            elif addresses:
                return addresses[0]
            else:
                return "No IP address found"

        except Exception as e:
            return f"Error: {str(e)}"

class SubdomainResolver:
    """Handles subdomain extraction and IP resolution."""
    def __init__(self, ip_resolver: IPResolverStrategy):
        self.ip_resolver = ip_resolver
    
    def extract_common_names(self, json_file: str):
        """Extracts common subdomain names from a JSON file."""
        with open(json_file, "r") as file:
            data = json.load(file)
        
        common_names = {entry["name_value"] for entry in data if not entry["name_value"].startswith("*")}
        return sorted(common_names)
    
    def resolve_subdomains(self, subdomains):
        """Resolves IP addresses for a list of subdomains."""
        for subdomain in subdomains:
            print(f"{subdomain} : {self.ip_resolver.get_ip_address(subdomain)}")
    
    def process_json_subdomains(self, json_file: str):
        """Processes subdomains from a JSON file and resolves IPs."""
        subdomains = self.extract_common_names(json_file)
        self.resolve_subdomains(subdomains)
    
    def process_excel_subdomains(self, excel_file: str):
        """Processes subdomains from an Excel file and resolves IPs."""
        df = pd.read_excel(excel_file)
        self.resolve_subdomains(df["Host"])

if __name__ == "__main__":
    json_file = "Assignment_1/q3/crt_subdomain.json"
    excel_file = "Assignment_1/q3/dnsdumpster_csv.xlsx"
    
    resolver = SubdomainResolver(NSLookupResolver())
    
    print("----CRT Subdomains----\n")
    resolver.process_json_subdomains(json_file)
    
    print("\n----DNSDumpster----\n")
    resolver.process_excel_subdomains(excel_file)
