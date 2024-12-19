import sys
import os
import shutil
import psycopg2
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
                             QPushButton, QMessageBox, QHBoxLayout, QFileDialog, QComboBox)
from PyQt5.QtCore import pyqtSlot, Qt
from functools import partial


DB_CONFIG = {
    'dbname': 'projectbd',
    'user': 'mozgovojnikita',
    'password': 'Madlibb1',
    'host': 'localhost',
    'port': 5432,
}

def create_db():
    """Создание таблиц и базовых записей в базе данных"""
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Roles (
            id SERIAL PRIMARY KEY,
            role_name VARCHAR(255) NOT NULL UNIQUE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            role_id INTEGER REFERENCES Roles(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Files (
            id SERIAL PRIMARY KEY,
            filename VARCHAR(255) NOT NULL,
            filepath VARCHAR(1024) NOT NULL,
            role_id INTEGER REFERENCES Roles(id) ON DELETE SET NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS AccessRules (
            id SERIAL PRIMARY KEY,
            role_id INTEGER REFERENCES Roles(id) ON DELETE CASCADE,
            permission VARCHAR(255) NOT NULL
        )
    ''')

    cursor.execute('''
        INSERT INTO Roles (role_name)
        VALUES ('User'), ('Admin')
        ON CONFLICT (role_name) DO NOTHING
    ''')

    cursor.execute('''
        INSERT INTO AccessRules (role_id, permission)
        VALUES
            ((SELECT id FROM Roles WHERE role_name = 'User'), 'read_user'),
            ((SELECT id FROM Roles WHERE role_name = 'Admin'), 'read'),
            ((SELECT id FROM Roles WHERE role_name = 'Admin'), 'write')
        ON CONFLICT DO NOTHING
    ''')

    conn.commit()
    conn.close()


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Login')
        self.setGeometry(100, 100, 480, 320)

        layout = QVBoxLayout()

        self.username_label = QLabel('Username:', self)
        layout.addWidget(self.username_label)
        self.username_input = QLineEdit(self)
        layout.addWidget(self.username_input)

        self.password_label = QLabel('Password:', self)
        layout.addWidget(self.password_label)
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.login_button = QPushButton('Login', self)
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)

        self.register_button = QPushButton('Register', self)
        self.register_button.clicked.connect(self.open_register_window)
        layout.addWidget(self.register_button)

        self.exit_button = QPushButton('Exit', self)
        self.exit_button.clicked.connect(self.exit_app)
        layout.addWidget(self.exit_button)

        self.setLayout(layout)

    @pyqtSlot()
    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute('SELECT id, role_id FROM Users WHERE username=%s AND password=%s', (username, password))

        result = cursor.fetchone()
        conn.close()

        if result:
            user_id, role_id = result
            self.main_window = MainWindow(user_id, role_id)
            self.main_window.show()
            self.close()
        else:
            QMessageBox.warning(self, 'Error', 'Incorrect username or password')

    @pyqtSlot()
    def open_register_window(self):
        self.register_window = RegisterWindow()
        self.register_window.show()
        self.close()

    @pyqtSlot()
    def exit_app(self):
        QApplication.instance().quit()


class RegisterWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Register')
        self.setGeometry(100, 100, 480, 320)

        layout = QVBoxLayout()

        self.username_label = QLabel('Username:', self)
        layout.addWidget(self.username_label)
        self.username_input = QLineEdit(self)
        layout.addWidget(self.username_input)

        self.password_label = QLabel('Password:', self)
        layout.addWidget(self.password_label)
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.register_button = QPushButton('Register', self)
        self.register_button.clicked.connect(self.register)
        layout.addWidget(self.register_button)

        self.back_button = QPushButton('Back', self)
        self.back_button.clicked.connect(self.go_back)
        layout.addWidget(self.back_button)

        self.exit_button = QPushButton('Exit', self)
        self.exit_button.clicked.connect(self.exit_app)
        layout.addWidget(self.exit_button)

        self.setLayout(layout)

    @pyqtSlot()
    def register(self):
        username = self.username_input.text()
        password = self.password_input.text()

        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM Users WHERE username=%s', (username,))
        if cursor.fetchone():
            QMessageBox.warning(self, 'Error', 'Username already exists')
        else:
            cursor.execute(
                f'''INSERT INTO Users (username, password, role_id) VALUES ('{username}', '{password}', (SELECT id FROM Roles WHERE role_name = 'User'))''',
                )
            conn.commit()
            QMessageBox.information(self, 'Success', 'User registered successfully')
            self.go_back()
        conn.close()

    @pyqtSlot()
    def go_back(self):
        self.login_window = LoginWindow()
        self.login_window.show()
        self.close()

    @pyqtSlot()
    def exit_app(self):
        QApplication.instance().quit()


class MainWindow(QWidget):
    def __init__(self, user_id, role_id):
        super().__init__()
        self.setWindowTitle('Main Window')
        self.setGeometry(100, 100, 480, 320)

        self.user_id = user_id
        self.role_id = role_id

        layout = QVBoxLayout()

        self.label = QLabel('Resources', self)
        self.label.setAlignment(Qt.AlignCenter)
        font = self.label.font()
        font.setPointSize(16)
        self.label.setFont(font)
        layout.addWidget(self.label)

        self.resources_layout = QVBoxLayout()
        self.load_resources(self.resources_layout)

        resources_widget = QWidget()
        resources_widget.setLayout(self.resources_layout)
        layout.addWidget(resources_widget)

        if self.is_admin():
            self.admin_button = QPushButton('Admin Panel', self)
            self.admin_button.clicked.connect(self.open_admin_panel)
            layout.addWidget(self.admin_button)

            self.add_file_button = QPushButton('Add File', self)
            self.add_file_button.clicked.connect(self.open_add_file_window)
            layout.addWidget(self.add_file_button)

        self.unlogin_button = QPushButton('Unlogin', self)
        self.unlogin_button.clicked.connect(self.unlogin)
        layout.addWidget(self.unlogin_button)

        self.exit_button = QPushButton('Exit', self)
        self.exit_button.clicked.connect(self.exit_app)
        layout.addWidget(self.exit_button)

        self.setLayout(layout)

    def load_resources(self, layout):
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # Проверяем роль пользователя
        cursor.execute('SELECT role_name FROM Roles WHERE id=%s', (self.role_id,))
        role_name = cursor.fetchone()[0]

        if role_name == 'Admin':
            cursor.execute('SELECT filename, filepath FROM Files')
        else:
            cursor.execute(f'''
                SELECT F.filename, F.filepath
                FROM Files F
                JOIN AccessRules AR ON F.role_id = AR.role_id
                WHERE AR.permission IN ('read_user', 'read') AND AR.role_id = %s
            ''', (self.role_id,))

        files = cursor.fetchall()
        check = []
        for file in files:
            file_label = QLabel(file[0], self)

            download_button = QPushButton('Download', self)
            download_button.clicked.connect(partial(self.download_file, file[1]))

            delete_button = QPushButton('Delete', self)
            delete_button.clicked.connect(partial(self.delete_file, file[1]))

            file_layout = QHBoxLayout()
            file_layout.addWidget(file_label)
            file_layout.addWidget(download_button)
            file_layout.addWidget(delete_button)

            layout.addLayout(file_layout)

        conn.close()

    def has_permission(self, permission):
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM AccessRules WHERE role_id=%s AND permission=%s', (self.role_id, permission))
        has_perm = cursor.fetchone()[0] > 0
        conn.close()
        return has_perm

    def download_file(self, filepath):
        destination, _ = QFileDialog.getSaveFileName(self, 'Save File', os.path.basename(filepath))
        if destination:
            shutil.copyfile(filepath, destination)
            QMessageBox.information(self, 'Success', f'File downloaded to {destination}')
        else:
            QMessageBox.warning(self, 'Error', 'File download cancelled')

    def delete_file(self, filepath):
        if not self.has_permission('write'):
            QMessageBox.warning(self, 'Error', 'You do not have permission to delete files')
            return

        reply = QMessageBox.question(self, 'Delete File', 'Are you sure you want to delete this file?',
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            os.remove(filepath)
            conn = psycopg2.connect(**DB_CONFIG)
            cursor = conn.cursor()
            cursor.execute(f'''DELETE FROM Files WHERE filepath='{filepath}' ''')
            conn.commit()
            conn.close()
            self.hide()
            self.main_window = MainWindow(self.user_id, self.role_id)
            self.main_window.show()

    def is_admin(self):
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute('SELECT role_name FROM Roles WHERE id=%s', (self.role_id,))
        role_name = cursor.fetchone()[0]
        conn.close()
        return role_name == 'Admin'

    @pyqtSlot()
    def open_admin_panel(self):
        self.admin_window = AdminWindow(self)
        self.admin_window.show()
        self.close()

    @pyqtSlot()
    def open_add_file_window(self):
        self.add_file_window = AddFileWindow(self.user_id, self.role_id, self)
        self.add_file_window.show()
        self.hide()

    @pyqtSlot()
    def unlogin(self):
        self.login_window = LoginWindow()
        self.login_window.show()
        self.close()

    @pyqtSlot()
    def exit_app(self):
        QApplication.instance().quit()


class AddFileWindow(QWidget):
    def __init__(self, user_id, role_id, parent=None):
        super().__init__()
        self.setWindowTitle('Add File')
        self.setGeometry(100, 100, 480, 320)
        self.user_id = user_id
        self.role_id = role_id
        self.parent = parent

        layout = QVBoxLayout()

        self.filepath_label = QLabel('No file selected', self)
        layout.addWidget(self.filepath_label)

        self.select_file_button = QPushButton('Select File', self)
        self.select_file_button.clicked.connect(self.select_file)
        layout.addWidget(self.select_file_button)

        self.role_list = QComboBox(self)
        self.load_roles()
        layout.addWidget(self.role_list)

        self.add_file_button = QPushButton('Add File', self)
        self.add_file_button.clicked.connect(self.add_file)
        layout.addWidget(self.add_file_button)

        self.back_button = QPushButton('Back', self)
        self.back_button.clicked.connect(self.go_back)
        layout.addWidget(self.back_button)

        self.exit_button = QPushButton('Exit', self)
        self.exit_button.clicked.connect(self.exit_app)
        layout.addWidget(self.exit_button)

        self.setLayout(layout)

    def load_roles(self):
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()

        if self.is_admin():
            cursor.execute('SELECT id, role_name FROM Roles')
        else:
            cursor.execute('SELECT id, role_name FROM Roles WHERE role_name = "User"')

        roles = cursor.fetchall()

        for role in roles:
            self.role_list.addItem(role[1], role[0])

        conn.close()

    def is_admin(self):
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute('SELECT role_name FROM Roles WHERE id=%s', (self.role_id,))
        role_name = cursor.fetchone()[0]
        conn.close()
        return role_name == 'Admin'

    @pyqtSlot()
    def select_file(self):
        options = QFileDialog.Options()
        file, _ = QFileDialog.getOpenFileName(self, 'Select File', '', 'All Files (*)', options=options)
        if file:
            self.filepath_label.setText(file)
            self.selected_file = file

    @pyqtSlot()
    def add_file(self):
        try:
            filename = os.path.basename(self.selected_file)
            destination = os.path.join(os.getcwd(), filename)
            shutil.copyfile(self.selected_file, destination)
            filepath = destination
            role_id = self.role_list.currentData()

            conn = psycopg2.connect(**DB_CONFIG)
            cursor = conn.cursor()
            cursor.execute(f'''INSERT INTO Files (filename, filepath, role_id) VALUES ('{filename}', '{filepath}', {role_id})''')
            conn.commit()
            conn.close()

            QMessageBox.information(self, 'Success', 'File added successfully')

        except AttributeError:
            QMessageBox.warning(self, 'Error', 'No file selected')
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'An error occurred: {str(e)}')

    @pyqtSlot()
    def go_back(self):
        self.hide()
        self.main_window = MainWindow(self.user_id, self.role_id)
        self.main_window.show()

    @pyqtSlot()
    def exit_app(self):
        QApplication.instance().quit()


class AdminWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.setWindowTitle('Admin Panel')
        self.setGeometry(100, 100, 480, 320)
        self.parent = parent

        layout = QVBoxLayout()

        self.users_label = QLabel('Users:', self)
        layout.addWidget(self.users_label)

        self.users_list = QComboBox(self)
        self.load_users()
        layout.addWidget(self.users_list)

        self.roles_label = QLabel('Assign Role:', self)
        layout.addWidget(self.roles_label)

        self.roles_list = QComboBox(self)
        self.load_roles()
        layout.addWidget(self.roles_list)

        self.assign_role_button = QPushButton('Assign Role', self)
        self.assign_role_button.clicked.connect(self.assign_role)
        layout.addWidget(self.assign_role_button)

        self.back_button = QPushButton('Back', self)
        self.back_button.clicked.connect(self.go_back)
        layout.addWidget(self.back_button)

        self.exit_button = QPushButton('Exit', self)
        self.exit_button.clicked.connect(self.exit_app)
        layout.addWidget(self.exit_button)

        self.setLayout(layout)

    def load_users(self):
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username FROM Users')
        users = cursor.fetchall()
        for user in users:
            self.users_list.addItem(user[1], user[0])
        conn.close()

    def load_roles(self):
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute('SELECT id, role_name FROM Roles')
        roles = cursor.fetchall()
        for role in roles:
            self.roles_list.addItem(role[1], role[0])
        conn.close()

    @pyqtSlot()
    def assign_role(self):
        user_id = self.users_list.currentData()
        role_id = self.roles_list.currentData()

        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute('UPDATE Users SET role_id=%s WHERE id=%s', (role_id, user_id))
        conn.commit()
        conn.close()

        QMessageBox.information(self, 'Success', 'Role assigned successfully')

    @pyqtSlot()
    def go_back(self):
        if self.parent:
            self.parent.show()
        self.close()

    @pyqtSlot()
    def exit_app(self):
        QApplication.instance().quit()


if __name__ == '__main__':
    create_db()
    app = QApplication(sys.argv)
    login = LoginWindow()
    login.show()
    sys.exit(app.exec_())





