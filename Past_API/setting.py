from requests import get
import gzip
import pandas as pd
import datetime
import os.path


class Setting:
    datadump = "https://cve.circl.lu/static/circl-cve-search-expanded.json.gz"
    savedir = "../data/"
    savezip = ""
    savepath = ""

    def __init__(self):
        d = datetime.datetime.now()
        file_list = os.listdir(self.savedir)
        dataset_file = ""
        for name in file_list:
            if name in "cve_data" and name.split('.')[-1] in "xlsx":
                dataset_file = name
                break

        newFilename = "cve_data_" + datetime.datetime.today().strftime('%Y-%m') + "xlsx"
        if len(dataset_file) == 0 or newFilename != dataset_file:
            self.download_open()

    def download_open(self):
        self.savezip = self.savedir + "cve_data_" + datetime.datetime.today().strftime('%Y-%m') + ".json.gz"
        with get(self.datadump, stream=True) as r:
            r.raise_for_status()
            with open(self.savezip, "wb") as file:
               # pbar = tqdm(total=int(r.headers['Content-Length']))
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        file.write(chunk)
                        # pbar.update(len(chunk))
        self.savepath = self.savedir + "cve_data_" + datetime.datetime.today().strftime('%Y-%m') + ".json"
        with open(self.savepath, 'wb') as f:
            with gzip.open(self.savezip, 'rb') as ff:
                file_content = ff.read()
                f.write(file_content)
        json_df = pd.read_json(self.savepath, lines=True)
        json_df.to_excel(self.savedir + "cve_data_" + datetime.datetime.today().strftime('%Y-%m') + ".xlsx",engine='xlsxwriter')
