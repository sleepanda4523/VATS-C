from requests import get
import gzip
import pandas as pd
import numpy as np
import swifter
import datetime
import os.path
from cwe import Database

class Core:
    datadump = "https://cve.circl.lu/static/circl-cve-search-expanded.json.gz"
    dir = "./data/"
    savezip = ""
    savejson = ""
    db = Database()

    def plus_des(self, df):
        cwe_des = ['' for i in range(df.shape[0])]
        for i in range(0, df.shape[0]):
            num = df.iloc[i, 2].split('-')[1]
            if num == 'CWE':
                num = 0
            week = self.db.get(int(num))
            if week is None:
                cwe_des[i] = np.NaN
            else:
                cwe_des[i] = week.description
        df['CWE-DES'] = cwe_des
        return df

    def selectcpe(self, cpe_df):
        cpe_list = {'Type':[], 'Vendors':[], 'Product':[], 'Version':[]}
        for column_name, item in cpe_df.iteritems():    # TODO : "list index out of range"에러 수정 필요
            cpe_data = item[0].split(':')
            cpe_list['Type'].append(cpe_data[2])
            cpe_list['Vendors'].append(cpe_data[3])
            cpe_list['Product'].append(cpe_data[4])
            cpe_list['Version'].append(cpe_data[5])
        print('debug')
        cpe_df['Type'] = cpe_list['Type']
        cpe_df['Vendors'] = cpe_list['Vendors']
        cpe_df['Product'] = cpe_list['Product']
        cpe_df['Version'] = cpe_list['Version']
        return cpe_df

    def clean_dataset(self, df, del_col):
        # Modify Dataset
        subset_df = df.drop(df.loc[df['cvss'].isnull()].index)
        subset_df = subset_df.drop(subset_df.loc[subset_df['cwe'] == 'Unknown'].index)
        subset_df = subset_df.drop_duplicates(subset=['id']).sort_values(by='id')
        subset_df.drop(del_col, axis=1, inplace=True)
        return subset_df

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

    def makeCVSSdataset(self, df):
        cvss_df = df.sort_values(by='cvss', axis=0, ascending=False)
        cvss_df.reset_index().drop(['index'], axis=1)
        return cvss_df

    def makeFreqdataset(self, df):
        cwe_data = df.replace('Nop', np.NaN)['cwe'].value_counts(sort=True, dropna=True).reset_index(
            name='count')
        select_df = df.drop(['id', 'cvss'], axis=1)
        freq_df = pd.merge(cwe_data.rename(columns={'index': 'cwe'}), select_df.drop_duplicates(['cwe']))
        #freq_df = self.plus_des(freq_df)
        return freq_df

    def makeProductdataset(self, df):
        cpe_df = self.selectcpe(df['vulnerable_product'])
        return cpe_df



