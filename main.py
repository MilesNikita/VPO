import sys
import os
import shutil
import subprocess
import xmltodict
import yaml
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QPushButton, QFileDialog, QTabWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QTextEdit, QHeaderView
from datetime import datetime

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Поиск вредосного программного обеспечения")
        self.setGeometry(100, 100, 600, 400)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        self.tab_widget = QTabWidget()
        self.layout.addWidget(self.tab_widget)
        self.tab1 = QWidget()
        self.tab_widget.addTab(self.tab1, "Сканирование")
        self.tab1_layout = QVBoxLayout()
        self.tab1.setLayout(self.tab1_layout)
        self.scan_button = QPushButton("Выбор директории")
        self.scan_button.clicked.connect(self.select_directory)
        self.tab1_layout.addWidget(self.scan_button)
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(3)
        self.file_table.setHorizontalHeaderLabels(["Имя файла", "Объем файла (KB)", "Тип"])
        self.file_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tab1_layout.addWidget(self.file_table)
        self.report_button = QPushButton("Сохранить отчет")
        self.report_button.clicked.connect(self.save_report)
        self.tab1_layout.addWidget(self.report_button)
        self.tab2 = QWidget()
        self.tab_widget.addTab(self.tab2, "Отчет PeStudio")
        self.tab2_layout = QVBoxLayout()
        self.tab2.setLayout(self.tab2_layout)
        self.pestudio_report_textedit = QTextEdit()
        self.tab2_layout.addWidget(self.pestudio_report_textedit)

    def select_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Выбор директории для сканирования")
        if directory:
            self.populate_file_table(directory)
            self.generate_pestudio_report(directory)

    def populate_file_table(self, directory):
        self.file_table.setRowCount(0) 
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):  
                file_type = self.get_file_type(filepath)
                if file_type:
                    file_size = os.path.getsize(filepath)
                    row_position = self.file_table.rowCount()
                    self.file_table.insertRow(row_position)
                    self.file_table.setItem(row_position, 0, QTableWidgetItem(filename))
                    self.file_table.setItem(row_position, 1, QTableWidgetItem(str(file_size)))
                    self.file_table.setItem(row_position, 2, QTableWidgetItem(file_type))
                    if file_type.startswith('PE'):
                        self.copy_to_folder(filepath, file_type, directory)

    def generate_pestudio_report(self, directory):
        pestudio_path = "path_to_pestudio"  # Путь к exe pestudio
        report_files = []
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                  file_type = self.get_file_type(filepath)
            if file_type:
                subprocess.run([pestudio_path, "-nobanner", os.path.join(directory, filename)])
                report_files.append(filename + ".xml")
        report_text = ""
        for report_file in report_files:
            report_path = os.path.join(directory, report_file)
            if os.path.exists(report_path):
                with open(report_path, "r") as file:
                    xml_data = file.read()
                    report_dict = xmltodict.parse(xml_data)
                    yaml_data = yaml.dump(report_dict, default_flow_style=False)
                    report_text += yaml_data + "\n\n"
        self.pestudio_report_textedit.setText(report_text)

    def generate_yaml_report(self):
        selected_files = []
        for row in range(self.file_table.rowCount()):
            filename_item = self.file_table.item(row, 0)
            if filename_item:
                selected_files.append(filename_item.text())
        yaml_data = yaml.dump({"selected_files": selected_files}, default_flow_style=False)
        save_path, _ = QFileDialog.getSaveFileName(self, "Сохранение отчета YAML", "", "YAML файл (*.yaml *.yml)")
        if save_path:
            with open(save_path, "w") as file:
                file.write(yaml_data)

    def get_file_type(self, file_path):
        __BUFFER_SIZE = 1000
        try:
            with open(file_path, 'rb') as file:
                buffer = file.read(__BUFFER_SIZE)
        except FileNotFoundError:
            return None
        e_ifanew = int.from_bytes(buffer[0x3c:0x40], byteorder='little')
        mz_signature = buffer[0x0:0x2]
        pe_signature = buffer[e_ifanew:e_ifanew + 0x4]
        magic = buffer[e_ifanew + 0x18:e_ifanew + 0x1a]
        if mz_signature == b'MZ' and pe_signature == b'PE\x00\x00':
            if magic == b'\x0b\x01':
                return 'PE32 Windows Executable'
            elif magic == b'\x0b\x02':
                return 'PE64 Windows Executable'
            elif magic == b'\x07\x01':
                return 'ROM Image'
        return None

    def copy_to_folder(self, filepath, file_type, source_directory):
        now = datetime.now()
        folder_name = now.strftime("%Y_%m_%d_%H_%M_%S") + "_" + file_type.replace(" ", "_")
        destination_folder = os.path.join(source_directory, folder_name)
        os.makedirs(destination_folder, exist_ok=True)
        shutil.copy(filepath, destination_folder)

    def save_report(self):
        print("тртртр")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
