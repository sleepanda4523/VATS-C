from requests import get
import gzip
import pandas as pd
import datetime
import os.path


class Setting:
    datadump = "https://cve.circl.lu/static/circl-cve-search-expanded.json.gz"
    savedir = "../data/"
    savezip = ""
    savepath = "../data/cve_data.json"
    status = ""

    def __init__(self):
        d = datetime.datetime.now()
        file_list = os.listdir(self.savedir)
        gzip_file = ""
        for i in file_list:
            text = i.split('.')[-1]
            if text in "gz":
                gzip_file = i
                break

        newFilename = self.savedir + "cve_data_" + datetime.datetime.today().strftime('%Y-%m') + ".json.gz"
        if len(gzip_file) == 0:
            self.savezip = newFilename
            status = "None"
        else:
            gzip_file = self.savedir + gzip_file
            if newFilename != gzip_file:
                self.savezip = newFilename
                status = "Update"
            else:
                self.savezip = gzip_file
                status = "Had"

    def download(self):
        with get(self.datadump, stream=True) as r:
            r.raise_for_status()
            with open(self.savezip, "wb") as file:
               # pbar = tqdm(total=int(r.headers['Content-Length']))
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        file.write(chunk)
                        # pbar.update(len(chunk))

    def open_gz(self):
        with open(self.savepath, 'wb') as f:
            with gzip.open(self.savezip, 'rb') as ff:
                file_content = ff.read()
                f.write(file_content)

    def clean_dataset(self, sy, ey):
        json_df = pd.read_json(self.savepath, lines=True)
        json_df.to_excel(self.savedir + 'dataset.xlsx',engine='xlsxwriter')

# testing code
# if __name__ == "__main__" :
#     test = MakeDataset()
#     test.clean_dataset(2019,2020)
