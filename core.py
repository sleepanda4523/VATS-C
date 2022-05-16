from requests import get
import gzip
import pandas as pd
import datetime
import os.path

class Core:
    datadump = "https://cve.circl.lu/static/circl-cve-search-expanded.json.gz"
    dir = "./data/"
    savezip = ""
    savejson = ""

    def checkfile(self):
        d = datetime.datetime.now()
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)
            return 0
        else :
            file_list = os.listdir(self.dir)
            dataset = ""
            zipFile = ""
            for name in file_list:
                if ".gz" in name and "cve_data" in name :
                    zipFile = name
                if ".xlsx" in name and "cve_data" in name:
                    dataset = name

            print(zipFile)
            newZipname = "cve_data_" + datetime.datetime.today().strftime('%Y-%m') + ".json.gz"
            newFilename = "cve_data_" + datetime.datetime.today().strftime('%Y-%m') + ".xlsx"
            if newZipname not in file_list:
                if zipFile in file_list:
                    os.remove(self.dir + zipFile)
                return -1
            elif newFilename not in file_list:
                if dataset in file_list:
                    os.remove(self.dir + dataset)
                return 0
            return 1

