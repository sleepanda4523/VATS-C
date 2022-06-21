import sys
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from core import Core

from urllib import request
import gzip
import pandas as pd
import dask.dataframe as dd
import datetime
import os.path
import time

combobox = ['CVSS', 'CWE', 'Product']
deletecol = ['Modified', 'access', 'assigner', 'capec', 'last-modified', 'vulnerable_configuration'
    , 'vulnerable_configuration_cpe_2_2', 'refmap', 'redhat', 'oval', 'saint', 'statements', 'd2sec', 'msbulletin'
]

class QComboBox(QComboBox):
    def __init__(self, parent = None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Fixed)


class TheradDownload(QThread):
    pbar_value = pyqtSignal(int)
    end_signal = pyqtSignal()

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

    def Handle_Progress(self, blocknum, blocksize, totalsize):
        ## calculate the progress
        readed_data = blocknum * blocksize

        if totalsize > 0:
            download_percentage = readed_data * 100 / totalsize
            self.pbar_value.emit(int(download_percentage))
            QApplication.processEvents()

    def run(self):
        down_url = "https://cve.circl.lu/static/circl-cve-search-expanded.json.gz"
        self.parent.savezip = self.parent.dir + "cve_data_" + datetime.datetime.today().strftime('%Y-%m') + ".json.gz"
        request.urlretrieve(down_url, self.parent.savezip, self.Handle_Progress)
        self.end_signal.emit()
        self.stop()

    def stop(self):
        self.power = False
        self.quit()
        self.wait(3000)


class TheradUnzip(QThread, Core):
    label_signal = pyqtSignal(str)
    end_signal = pyqtSignal()
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

    def run(self):
        self.label_signal.emit('unzip dataset file..')
        today = datetime.datetime.today().strftime('%Y-%m')
        cve_df_name = self.dir + "cve_data_" + today + ".xlsx"
        self.savezip = self.dir + "cve_data_" + today + ".json.gz"
        self.savejson = self.dir + "cve_data_" + today + ".json"
        with open(self.savejson, 'wb') as f:
            with gzip.open(self.savezip, 'rb') as ff:
                file_content = ff.read()
                f.write(file_content)
        self.label_signal.emit('make dataset file..')
        json_df = pd.read_json(self.savejson, lines=True)
        json_df = self.clean_dataset(json_df, deletecol)
        json_df.to_excel(cve_df_name, engine='xlsxwriter')
        os.remove(self.savejson)

        self.label_signal.emit('make cvss dataset file..')
        cvss_df = self.makeCVSSdataset(json_df)
        cvss_df.to_excel(self.dir + "cve_data_cvss_"+today+".xlsx", engine='xlsxwriter')

        self.label_signal.emit('make cwe dataset file..')
        cwe_df = self.makeCWEdataset(json_df)
        cwe_df.to_excel(self.dir + "cve_data_cwe_" + today + ".xlsx", engine='xlsxwriter')

        self.label_signal.emit('make product dataset file..')
        product_df = self.makeProductdataset(json_df)
        product_df.to_excel(self.dir + "cve_data_product_" + today + ".xlsx", engine='xlsxwriter')
        self.end_signal.emit()

    def stop(self):
        self.power = False
        self.quit()
        self.wait(3000)


class ThreadUpload(QThread, Core):
    label_signal = pyqtSignal(str)
    end_signal = pyqtSignal(object)

    def __init__(self, parent, s1, s2):
        super().__init__(parent)
        self.parent = parent
        self.s1 = s1
        self.s2 = s2

    def run(self):
        today = datetime.datetime.today().strftime('%Y-%m')
        d1 = self.optimize(pd.read_excel(self.dir + "cve_data_" + self.s1.lower() + "_" + today + ".xlsx"), ['Published', 'cvss-time']).iloc[:, 1:]
        d2 = self.optimize(pd.read_excel(self.dir + "cve_data_" + self.s2.lower() + "_" + today + ".xlsx"), ['Published', 'cvss-time']).iloc[:, 1:]

        #print(d1.info(memory_usage='deep'), d2.info(memory_usage='deep'))

        self.label_signal.emit("Merge Dataset...")

        result_df = pd.merge(d1, d2, on=list(set(d1.columns) & set(d2.columns)), how='left')
        result_df = result_df.drop_duplicates()
        print(result_df.info)
        self.end_signal.emit(result_df)


class ThreadSave(QThread, Core):
    label_signal = pyqtSignal(str)
    end_signal = pyqtSignal()

    def __init__(self, file, df):
        super().__init__()
        self.FileSave = file
        self.df = df

    def run(self):
        self.label_signal.emit("Save Dataset...")
        today = datetime.datetime.today().strftime('%Y-%m')
        self.df.to_excel(self.FileSave[0]+'result.xlsx', index_label=False, engine='xlsxwriter')
        self.end_signal.emit()




class Download(QDialog, Core):
    savezip = ""

    def __init__(self):
        super().__init__()
        self.setWindowTitle('Download')
        self.setWindowModality(Qt.ApplicationModal)
        self.resize(500, 500)
        self.initUI()

    def initUI(self):
        self.label = QLabel("Download CVE Datadump File..", self)
        self.label.setAlignment(Qt.AlignCenter)

        font = self.label.font()
        font.setPointSize(15)
        font.setFamily("Noto Sans")

        self.label.setFont(font)
        self.pbar = QProgressBar(self)
        self.pbar.setRange(0,100)

        layout = QVBoxLayout()
        layout.addStretch(1)
        layout.addWidget(self.label)
        layout.addWidget(self.pbar)
        layout.addStretch(1)
        self.setLayout(layout)
        self.show()

    def start(self):
        d = TheradDownload(self)
        d.pbar_value.connect(self.pbar.setValue)
        d.start()
        d.end_signal.connect(self.open)

    def open(self):
        d = TheradUnzip(self)
        self.pbar.setRange(0, 0)
        d.label_signal.connect(self.label.setText)
        d.end_signal.connect(self.close)
        d.start()


class Upload(QDialog, Core):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Upload')
        self.setWindowModality(Qt.ApplicationModal)
        self.resize(400, 400)
        self.initUI()

    def initUI(self):
        self.label = QLabel("Read dataset Files...", self)
        self.label.setAlignment(Qt.AlignCenter)

        font = self.label.font()
        font.setPointSize(15)
        font.setFamily("Noto Sans")

        self.label.setFont(font)
        self.pbar = QProgressBar(self)
        self.pbar.setRange(0, 0)

        layout = QVBoxLayout()
        layout.addStretch(1)
        layout.addWidget(self.label)
        layout.addWidget(self.pbar)
        layout.addStretch(1)
        self.setLayout(layout)
        self.show()

    def getExcel(self, s1, s2):
        self.d = ThreadUpload(self, s1=s1, s2=s2)
        self.d.label_signal.connect(self.label.setText)
        self.d.start()
        self.d.end_signal.connect(self.open)

    def open(self, df):
        Filename = QFileDialog.getExistingDirectory(self, 'Save result', './')
        self.d = ThreadSave(file=Filename, df=df)
        self.d.label_signal.connect(self.label.setText)
        self.d.start()
        self.d.end_signal.connect(self.close)


class MainWidget(QWidget, Core):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # comboBoxs
        lbl1 = QLabel("Select1: ")
        lbl1.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Ignored)

        lbl2 = QLabel("Select2: ")
        lbl2.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Ignored)

        select1 = QComboBox(self)
        select1.addItems(combobox)
        select2 = QComboBox(self)
        select2.addItems(combobox)

        comboLayout = QGridLayout()
        comboLayout.addWidget(lbl1, 0, 0)
        comboLayout.addWidget(lbl2, 1, 0)
        comboLayout.addWidget(select1, 0, 1)
        comboLayout.addWidget(select2, 1, 1)

        download_btn = QPushButton('Download Result', self)
        download_btn.clicked.connect(lambda : self.selectdataset(select1.currentText(), select2.currentText()))
        download_btn.setMinimumSize(100, 50)
        download_btn.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        comboLayout.addItem(QSpacerItem(30, 0, QSizePolicy.Fixed, QSizePolicy.Ignored), 0, 2)
        comboLayout.addWidget(download_btn, 0, 3, 2, 1)

        self.setLayout(comboLayout)

    def selectdataset(self, s1, s2):
        self.d = Upload()
        self.d.getExcel(s1, s2)



class MainWindow(QMainWindow, Core):
    def __init__(self):
        super().__init__()
        self.initUI()
        check = self.checkfile()
        print(check)
        if check != 1:
            self.dialog = Download()
            if check == -1:
                self.dialog.start()
            elif check == 0:
                self.dialog.open()

    def menubar(self):
        exitAction = QAction('Exit', self)
        exitAction.setShortcut('Alt+F4')
        exitAction.triggered.connect(qApp.quit)

        updateAction = QAction('Update Dataset', self)
        updateAction.setShortcut('Ctrl+Q')
        #updateAction.triggered.connect()

        graphAction = QAction('Make Graph', self)
        graphAction.setShortcut('Ctrl+G')

        menubar = self.menuBar()
        menubar.setNativeMenuBar(False)
        menubar.addMenu('&File').addAction(exitAction)
        menubar.addMenu('&Edit').addAction(updateAction)
        menubar.addMenu('&Tools').addAction(graphAction)

    def initUI(self):
        self.mainWidget = MainWidget()
        self.menubar()
        self.setCentralWidget(self.mainWidget)
        self.setWindowTitle('VATS-C')
        self.setWindowIcon(QIcon("icons/bat.png"))
        self.setMinimumSize(320, 420)
        self.setGeometry(800, 300, 640, 640)


if __name__ == '__main__':
   app = QApplication(sys.argv)
   ex = MainWindow()
   ex.show()
   sys.exit(app.exec_())