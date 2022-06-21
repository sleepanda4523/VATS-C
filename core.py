from requests import get
import gzip
import pandas as pd
import numpy as np
import swifter
import datetime
import os.path
from cwe import Database
from typing import List

class Core:
    datadump = "https://cve.circl.lu/static/circl-cve-search-expanded.json.gz"
    dir = "./data/"
    savezip = ""
    savejson = ""
    db = Database()

    def optimize_floats(self, df: pd.DataFrame) -> pd.DataFrame:
        floats = df.select_dtypes(include=['float64']).columns.tolist()
        df[floats] = df[floats].apply(pd.to_numeric, downcast='float')
        return df

    def optimize_ints(self, df: pd.DataFrame) -> pd.DataFrame:
        ints = df.select_dtypes(include=['int64']).columns.tolist()
        df[ints] = df[ints].apply(pd.to_numeric, downcast='integer')
        return df

    def optimize_objects(self, df: pd.DataFrame, datetime_features: List[str]) -> pd.DataFrame:
        for col in df.select_dtypes(include=['object']):
            if col not in datetime_features:
                if not (type(df[col][0]) == list):
                    num_unique_values = len(df[col].unique())
                    num_total_values = len(df[col])
                    if float(num_unique_values) / num_total_values < 0.5:
                        df[col] = df[col].astype('category')
            else:
                df[col] = pd.to_datetime(df[col])
        return df

    def optimize(self, df: pd.DataFrame, datetime_features: List[str] = []):
        return self.optimize_floats(self.optimize_ints(self.optimize_objects(df, datetime_features)))


    def plus_des(self, df):
        cwe_des = ['' for i in range(df.shape[0])]
        for i in range(0, df.shape[0]):
            num = df.iloc[i, 0].split('-')[1]
            if num == 'CWE':
                num = 0
            week = self.db.get(int(num))
            if week is None:
                cwe_des[i] = np.NaN
            else:
                cwe_des[i] = week.description
        df['cwe-des'] = cwe_des
        return df

    def selectcpe(self, cpe_df):
        cpe_list = {'Type':[], 'Vendors':[], 'Product':[], 'Version':[]}
        for column_name, item in cpe_df.iteritems():
            if item:
                cpe_data = item[0].split(':')
                cpe_list['Type'].append(cpe_data[2])
                cpe_list['Vendors'].append(cpe_data[3])
                cpe_list['Product'].append(cpe_data[4])
                if cpe_data[5] != '-':
                    cpe_list['Version'].append(cpe_data[5])
                else:
                    cpe_list['Version'].append('*')
            else:
                cpe_list['Type'].append('*')
                cpe_list['Vendors'].append('*')
                cpe_list['Product'].append('*')
                cpe_list['Version'].append('*')
        return cpe_list

    def clean_dataset(self, df, del_col):
        # year filter
        year = [i for i in range(2020, 2022 + 1)] # TODO : 임시.
        year_str = ""
        for i in year:
            year_str += ('CVE-' + str(i) + '|')
        year_str = year_str[:-1]
        contain = df['id'].str.contains(year_str)
        subset_df = df[contain].sort_values(by='id')
        # Modify Dataset
        subset_df = subset_df.drop(subset_df.loc[subset_df['cvss'].isnull()].index)
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

    def makeCWEdataset(self, df):
        cwe_data = df.replace('Nop', np.NaN)['cwe'].value_counts(sort=True, dropna=True).reset_index(
            name='count')

        cwe_df = cwe_data.rename(columns={'index': 'cwe'})
        print(cwe_df)
        cwe_df = self.plus_des(cwe_df)
        return cwe_df

    def makeProductdataset(self, df):
        cpe_list = self.selectcpe(df['vulnerable_product'])
        for i in cpe_list.keys():
            df[i] = cpe_list[i]
        return df



