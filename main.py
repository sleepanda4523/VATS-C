import sys
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from core import Core

from urllib import request
import gzip
import pandas as pd
import datetime
import os.path
import time

combobox = ['CVSS', 'CWE', 'Product']


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

        try :
            self.savezip = self.dir + "cve_data_" + datetime.datetime.today().strftime('%Y-%m') + ".json.gz"
            self.savejson = self.dir + "cve_data_" + datetime.datetime.today().strftime('%Y-%m') + ".json"
            with open(self.savejson, 'wb') as f:
                with gzip.open(self.savezip, 'rb') as ff:
                    file_content = ff.read()
                    f.write(file_content)
            self.label_signal.emit('make dataset file..')
            json_df = pd.read_json(self.savejson, lines=True)
            json_df.to_excel(self.dir + "cve_data_" + datetime.datetime.today().strftime('%Y-%m') + ".xlsx", engine='xlsxwriter')
            os.remove(self.savejson)
            self.end_signal.emit()
        except Exception as e:
            print(e)

    def stop(self):
        self.power = False
        self.quit()
        self.wait(3000)

class Download(QDialog, Core):
    dir = "./data/"
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
        self.pbar.close()
        d.label_signal.connect(self.label.setText)
        d.end_signal.connect(self.close)
        d.start()


class MainWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        select1 = QComboBox(self)
        select2 = QComboBox(self)
        select1.setFixedSize(120, 60)
        select2.setFixedSize(120, 60)
        select1.addItems(combobox)
        select2.addItems(combobox)

        # layout
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(select1)
        hbox.addStretch(1)
        hbox.addWidget(select2)
        hbox.addStretch(1)

        vbox = QVBoxLayout()
        vbox.addLayout(hbox)
        vbox.addStretch(4)

        self.setLayout(vbox)





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
        self.setMinimumSize(480, 320)
        self.setGeometry(800, 300, 960, 640)


if __name__ == '__main__':
   app = QApplication(sys.argv)
   ex = MainWindow()
   ex.show()
   sys.exit(app.exec_())