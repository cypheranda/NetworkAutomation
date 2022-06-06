#!venv/bin/python
import html
import os
import ipaddress
import re
import shutil
from _datetime import datetime
import uuid

import flask
import flask_user
from sqlalchemy.orm import backref
from wtforms import PasswordField, StringField, form, Form
from wtforms.validators import DataRequired, Length, EqualTo

from flask_admin.contrib.sqla.fields import QuerySelectField
from flask_wtf import FlaskForm
from werkzeug.datastructures import MultiDict
from wtforms import PasswordField, StringField, form, Form, SelectField, IntegerField, HiddenField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask import Flask, url_for, redirect, render_template, request, abort, jsonify, Markup, json
from flask_admin.contrib.sqla.filters import IntGreaterFilter
from flask_admin.contrib.sqla.view import func
from flask_admin.model import typefmt
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
from flask_security.utils import encrypt_password
import flask_admin
import flask_login
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers, AdminIndexView, Admin
from flask_admin import BaseView, expose
from flask_user import UserManager
from sqlalchemy import true
from sqlalchemy.ext.hybrid import hybrid_property
from wtforms import PasswordField
from flask_admin.form import SecureForm, fields
from flask_admin.contrib.sqla import ModelView
from flask import Flask, render_template, request, url_for, flash, redirect
from wtforms import validators

# ...
# scripts import
from templates.myscripts import netmiko_show_version, netmiko_get_devices_array, ping, paramiko_sh_ip_int_brief, \
    netmiko_check_autosecure_config, autosecure, napalm_check_connectivity
from templates.myscripts import netmiko_get_inventory_elements, napalm_retrieve_info
from templates.myscripts import netmiko_show, netmiko_run_commands_from_file, secure_boot, dai, \
    netmiko_before_loadbackup, netmiko_scp
from templates.myscripts import copy_files_frommaintarget, stp, tftp_transfer, napalm_ip_source_guard, setup_ftp
from templates.myscripts import netmiko_ospf, dhcp_server, dhcp_snooping
from passlib.hash import sha256_crypt
import json
from os.path import join, dirname, realpath

# ...
# scripts import
from templates.myscripts import netmiko_show_version, netmiko_get_devices_array, ping, paramiko_sh_ip_int_brief

# Create Flask application
app = Flask(__name__)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# Define models
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __str__(self):
        return self.name


# class Network(db.Model, RoleMixin):
#     __tablename__ = 'network'
#     id = db.Column(db.Integer(), primary_key=True)
#     name = db.Column(db.String(80), unique=True)
#     description = db.Column(db.String(255))
#
#     # devices = db.relationship("Device")
#     def __str__(self):
#         return self.name


class Device(db.Model, RoleMixin):
    __tablename__ = 'device'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    ip_address = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    src_file = db.Column(db.String(80), nullable=True)
    dest_file = db.Column(db.String(80), nullable=True)
    ping_now = db.Column(db.String(80), nullable=True)

    # network_id = db.Column(db.Integer(), db.ForeignKey('network.id'), nullable=False)
    # network = db.relationship("Network")

    # @hybrid_property
    # def ping(self):
    #
    # ip_address = self.ip_address
    # return ip_address
    # return ping.do_ping(ip_address)

    # @hybrid_property
    # def details(self):
    #     # details
    #     hostname, uptime, version, serial, ios = netmiko_show_version.show_version(self.ip_address, self.os_type,
    #                                                                                admin_username, admin_password)
    #     print(hostname)
    #     print(uptime)
    #     if hostname == "error":
    #         return "Could not connect to device!"
    #     data_array = []
    #     x = {
    #         "hostname": hostname,
    #         "uptime": uptime,
    #         "version": version,
    #         "serial": serial,
    #     }
    #     data_array.append(x)
    #     return json.dumps(data_array)
    #
    # @hybrid_property
    # def up_interfaces(self):
    #     # up_interfaces
    #     if self.ping != "Successful ping to host!" or self.details == "Could not connect to device!":
    #         return "Could not connect to device!"
    #     interfaces, int_ipaddresses = paramiko_sh_ip_int_brief.show_ipintbrief(self.ip_address, admin_username,
    #                                                                            admin_password, admin_enablepass)
    #     data_array = []
    #     x = {
    #         "interface": interfaces,
    #         "ip_address": int_ipaddresses,
    #         }
    #     return data_array.append(x)

    def __str__(self):
        return self.name


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), nullable=True)
    last_name = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    def __str__(self):
        return self.email


# user_manager = UserManager(app, db, User)

class Template(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def __str__(self):
        return self.name


class Inventory(db.Model, UserMixin):
    __tablename__ = 'inventory'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship("User")
    categories = db.relationship("Category", backref=backref("inventory", cascade="all,delete"))

    # devices = db.relationship("Device", backref="inventory")

    def __str__(self):
        return self.name


class Category(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    os_type = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    _password = db.Column(db.String(255), nullable=False)
    _enable_password = db.Column(db.String(255), nullable=False)
    inventory_id = db.Column(db.Integer, db.ForeignKey('inventory.id'), nullable=True)

    # inventory = db.relationship("Inventory", backref=backref('allcategories', cascade="all,delete"))

    def __str__(self):
        return self.name

    @hybrid_property
    def password(self):
        """Return the hashed user password."""
        return self._password

    @hybrid_property
    def enable_password(self):
        """Return the hashed user password."""
        return self._enable_password

    @password.setter
    def password(self, new_pass):
        """Salt/Hash and save the user's new password."""
        new_password_hash = sha256_crypt.encrypt(new_pass)
        self._password = new_password_hash

    @enable_password.setter
    def enable_password(self, new_enable_password):
        """Salt/Hash and save the user's new password."""
        new_password_hash = sha256_crypt.encrypt(new_enable_password)
        self._enable_password = new_password_hash


class DeviceCategoryRelation(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    category = db.relationship("Category", backref=backref('device_rel', cascade="all,delete"))
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    device = db.relationship("Device", backref=backref('category_rel', cascade="all,delete"))

    def __str__(self):
        return self.id


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


# Create customized model view class
class SuperuserModelView(sqla.ModelView):

    def is_accessible(self):
        if not current_user.is_active or not current_user.is_authenticated:
            return False

        if current_user.has_role('superuser'):
            return True

        return False

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))

    # can_edit = True
    edit_modal = True
    create_modal = True
    can_export = True
    can_view_details = True
    details_modal = True


class UserView(SuperuserModelView):
    column_editable_list = ['email']
    column_searchable_list = column_editable_list
    column_exclude_list = ['password', 'confirmed_at', 'active']
    # form_excluded_columns = column_exclude_list
    column_details_exclude_list = column_exclude_list
    column_filters = column_editable_list
    form_overrides = {
        'password': PasswordField
    }


@app.route("/searchping", methods=['GET'])
def get_data():
    # return "yes"
    ip_address = request.args.get('keyword')
    return ping.do_ping(ip_address)


class DeviceView(sqla.ModelView):
    column_list = ('name', 'ip_address', 'description', 'src_file', 'dest_file', 'ping_now')
    column_searchable_list = column_list
    # column_filters = ['name']

    can_view_details = False
    details_modal = True

    column_labels = {
        'src_file': 'Source file name to be moved',
        'dest_file': 'Destination file name',
    }

    form_excluded_columns = ['category_rel', 'ping_now']

    def _format_ping_now(self, context, model, name):
        content_id = model.id
        javascript = """
        
        function change(content_id){ //function to run when you click on the button...
            var buttonValue = document.getElementById("ping_"+content_id).value; //stores the button value
            var xmlHttp = new XMLHttpRequest();
            xmlHttp.open( "GET", '/searchping?keyword=' + buttonValue, false );
            xmlHttp.send();
            document.getElementById("myDiv_"+content_id).innerHTML = xmlHttp.responseText;; // displays the value as a plain text inside "myDiv" - removing the button input entirely           
}
        """

        style = """
#loader {
    position: absolute;
    left: 50%;
    top: 50%;
    z-index: 1;
    width: 150px;
    height: 150px;
    margin: -75px 0 0 -75px;
    border: 16px solid #f3f3f3;
    border-radius: 50%;
    border-top: 16px solid #3498db;
    width: 120px;
    height: 120px;
    -webkit-animation: spin 2s linear infinite;
    animation: spin 2s linear infinite;
}

@-webkit-keyframes spin {
    0% { -webkit-transform: rotate(0deg); }
    100% { -webkit-transform: rotate(360deg); }
  }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }"""

        _html = """
        <div id="myDiv_{content_id}">
        <input type="button" value="{ip_address}" id="ping_{content_id}" onClick="change({content_id})"> <!--button input that will trigger an event named change-->
    </div>
<script type="text/javascript">
{my_code}
</script>
<style>
{style}
</style>
                        """.format(my_code=javascript, content_id=content_id, ip_address=model.ip_address, style=style)
        return Markup(_html)

    column_formatters = {
        'ping_now': _format_ping_now
    }


class FullView(sqla.ModelView):
    column_list = ['category.inventory.name', 'category.name', 'device.name']
    column_searchable_list = column_list
    # column_filters = ['name']

    can_view_details = True
    details_modal = True

    column_labels = {
        'category.inventory.name': 'Inventory',
        'category.name': 'Category',
        'device.name': 'Device',
    }


def filter_inventories():
    return db.session.query(Inventory).filter_by(user_id=flask_login.current_user.id)


def filter_ostypes():
    return "ios"


class CategoryView(sqla.ModelView):
    column_list = ['name', 'inventory', 'os_type', 'username']
    column_exclude_list = ['_password', '_enable_password']
    column_editable_list = column_list
    column_searchable_list = ['name']
    column_filters = ['name', 'inventory.name']
    # form_extra_fields = ['password', 'enable']

    can_view_details = False
    details_modal = True

    column_labels = {
        'name': 'Name',
        'inventory.name': 'Inventory',
    }

    form_args = {
        "inventory": {
            "query_factory": filter_inventories
        }
    }

    form_choices = {"os_type": [('ios', 'ios'), ]}

    form_extra_fields = {
        'password': PasswordField('Password', [validators.DataRequired(),
                                               validators.EqualTo('confirm_password', message='Passwords must match')]),
        'confirm_password': PasswordField('Confirm password', [validators.DataRequired()]),
        'enable_password': PasswordField('Enable password', [validators.DataRequired(),
                                                             validators.EqualTo('confirm_enable_password',
                                                                                message='Enable passwords must match')]),
        'confirm_enable_password': PasswordField('Confirm enable password', [validators.DataRequired()])
    }

    form_excluded_columns = ['device_rel']

    column_labels = {
        'name': 'Name',
        'inventory.name': 'Inventory',
    }


def filter_func():
    curr_usr = User.query.filter_by(id=flask_login.current_user.id).first()
    return db.session.query(User).filter_by(email=curr_usr.email)


class InventoryView(sqla.ModelView):
    column_editable_list = ['name']
    column_searchable_list = column_editable_list
    column_filters = None

    can_view_details = False
    details_modal = True

    form_args = {
        "user": {
            "query_factory": filter_func
        }
    }

    form_excluded_columns = ('categories')

    def get_query(self):
        return self.session.query(self.model).filter(self.model.user_id == flask_login.current_user.id)

    def get_count_query(self):
        return self.session.query(func.count('*')).filter(self.model.user_id == flask_login.current_user.id)


class TemplateView(BaseView):
    @expose('/')
    def index(self):
        templates = Template.query.order_by(Template.name).all()
        return self.render('admin/templates.html', templates=templates)


# Flask views
@app.route('/')
def index():
    return render_template('index.html')


class MyView(BaseView):
    def __init__(self, *args, **kwargs):
        self._default_view = True
        super(MyView, self).__init__(*args, **kwargs)
        self.admin = admin


def validate_ip_address(address):
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def validate_mac_address(address):
    if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", address.lower()):
        return True
    else:
        return False


def split_string(text):
    words = text.split(",")
    return words


def check_range(text):
    if text.isdigit() == True:
        return 1
    elif '-' not in text:
        return 0
    else:
        range_array = text.split("-")
        if len(range_array) != 2:
            return 0
        else:
            if range_array[0].isdigit() == False:
                return 0
            if range_array[1].isdigit() == False:
                return 0
            return 1


def adjust_file(inv_file, password_str, enable_str):
    filename = str(uuid.uuid4())
    original_path = 'templates/myscripts/inventories/' + inv_file
    original_file_path = os.path.join(ROOT_DIR, original_path)  # requires `import os`
    new_path = 'templates/myscripts/inventories/' + filename
    new_file_path = os.path.join(ROOT_DIR, new_path)  # requires `import os`
    shutil.copyfile(original_file_path, new_file_path)

    new_lines = []
    filein = open(new_file_path, "r")
    for line in filein:
        if 'ansible_password=' in line:
            line = "ansible_password=" + password_str + '\n'
        elif 'ansible_ssh_pass=' in line:
            line = "ansible_ssh_pass=" + password_str + '\n'
        elif 'ansible_become_password' in line:
            line = "ansible_become_password=" + enable_str + '\n'
        new_lines.append(line)
    filein.close()

    fileout = open(new_file_path, "w+")
    for line in new_lines:
        fileout.write(line)
    fileout.close()
    return new_file_path


def write_inventory_files(filenames):
    path = 'templates/myscripts/inventories/'
    dir = os.path.join(ROOT_DIR, path)  # requires `import os`
    for f in os.listdir(dir):
        os.remove(os.path.join(dir, f))
    for filename in filenames:
        path = 'templates/myscripts/inventories/' + filename.name
        file_path = os.path.join(ROOT_DIR, path)  # requires `import os`
        filein = open(file_path, "w+")
        all_categories = Category.query.filter_by(inventory_id=filename.id).all()
        categories = []
        for each_category in all_categories:
            entry = DeviceCategoryRelation.query.filter_by(category=each_category).all()
            if entry:
                categories.append(each_category)
        for category in categories:
            relations = category.device_rel
            filein.write('[' + category.name + ']\n')
            # check for duplicates
            res_relations = []
            for x in relations:
                exists = 0
                for y in res_relations:
                    if x.category_id == y.category_id and x.device_id == y.device_id:
                        exists = 1
                if exists == 0:
                    res_relations.append(x)

            for relation in res_relations:
                filein.write(relation.device.name + ' ansible_host=' + relation.device.ip_address)
                idk = relation.device.src_file
                if relation.device.src_file != None and relation.device.dest_file != None:
                    filein.write(' src_file=' + relation.device.src_file + ' dest_file=' + relation.device.dest_file)
                filein.write('\n')
            filein.write('\n')
            filein.write('[' + category.name + ':vars]\n')
            filein.write('ansible_network_os=' + category.os_type + '\n')
            filein.write('ansible_user=' + category.username + '\n')
            filein.write('ansible_password=' + category.password + '\n')
            filein.write('ansible_ssh_pass=' + category.password + '\n')
            filein.write('ansible_become=yes\n')
            filein.write('ansible_become_method=enable\n')
            filein.write('ansible_become_password=' + category.enable_password + '\n')
            filein.write('ansible_connection=network_cli\n')
            filein.write('ansible_python_interpreter=/usr/bin/python3\n')
            filein.write('\n')

        filein.close()


@app.route('/fetch_config', methods=['POST'])
def send_data():
    json = request.json
    inputUsername = json['username']
    inputPassword = json['password']
    inputEnablePassword = json['enable']
    inputInventory = json['inventory']
    inputDevices = json['devices']

    if not inputDevices:
        return 'Devices are required!'
    else:
        inv_path = 'templates/myscripts/inventories/' + inputInventory
        original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
        devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
            original_inv_path, inputDevices)
        if ((devices_username != inputUsername) or (
                sha256_crypt.verify(inputPassword, devices_password) != True) or (
                sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
            return "These are not the credentials from the inventory file! Please reconfigure the file accordingly."
        else:
            inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
            # run playbook here
            ansible_cmd = "ansible-playbook -i {0} ios_show_run.yaml --extra-vars \"variable_host={1}\"".format(
                inputInventory, inputDevices)
            # to run this cmd

            output = os.popen(ansible_cmd).read()
            os.remove(inputInventory)
            return output


@app.route('/fetch_backups', methods=['POST', 'GET'])
def get_backups():
    myjson = request.json
    inventory = myjson['inventory']
    devices = myjson['devices']

    # get all backup files array
    small_path = 'templates/myscripts/backup'
    BACKUPS_PATH = os.path.join(ROOT_DIR, small_path)  # requires `import os`
    mylist = os.listdir(BACKUPS_PATH)

    # get devices array
    my_category = Category.query.filter_by(name=devices).first()
    devices_array = DeviceCategoryRelation.query.filter_by(category=my_category).all()

    # get backup files for these devices
    obj_list = {}
    for device_rel in devices_array:
        my_array = []
        for filename in mylist:
            if device_rel.device.name+"_config" in filename:
                my_array.append(filename)
        obj_list[device_rel.device.name] = my_array

    return_json = json.dumps(obj_list)
    return return_json


@app.route('/admin/<template_type>', methods=['POST', 'GET'])
def find_template(template_type):
    user_inventory_rel = Inventory.query.filter_by(user_id=flask_login.current_user.id).all()
    inventories = []
    for relation in user_inventory_rel:
        inventories.append(Inventory.query.filter_by(name=relation.name).first())
    write_inventory_files(inventories)

    myDict = {}
    for inventory in inventories:
        key = inventory.name

        # select all devices categories for each inventory
        devices = []
        path = 'templates/myscripts/inventories/' + inventory.name
        CONFIG_PATH = os.path.join(ROOT_DIR, path)  # requires `import os`

        devices = netmiko_get_inventory_elements.get_device_data(CONFIG_PATH)

        # list
        myDict[key] = devices

        devicesDict = {}

        for device_category in devices:
            device_hostnames = netmiko_get_devices_array.get_device_data(CONFIG_PATH, device_category)[0]
            devicesDict[device_category] = device_hostnames

    if request.method == 'POST':
        path = 'templates/myscripts/'
        scripts_path = os.path.join(ROOT_DIR, path)
        if template_type == "Autosecure":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputType = request.form['inputType']
            inputSecurityBanner = request.form['inputSecurityBanner']
            inputNewEnableSecret = request.form['inputNewEnableSecret']
            inputConfirmNewEnableSecret = request.form['inputConfirmNewEnableSecret']
            inputNewEnablePassword = request.form['inputNewEnablePassword']
            inputConfirmNewEnablePassword = request.form['inputConfirmNewEnablePassword']
            inputLocalUsername = request.form['inputLocalUsername']
            inputLocalPassword = request.form['inputLocalPassword']
            inputConfirmLocalPassword = request.form['inputConfirmLocalPassword']
            inputBlockingPeriod = request.form['inputBlockingPeriod']
            inputLoginFailures = request.form['inputLoginFailures']
            inputTimePeriod = request.form['inputTimePeriod']
            inputSSHOption = request.form['inputSSHOption']
            inputHostname = request.form['inputHostname']
            inputDomainName = request.form['inputDomainName']
            inputFirewallOption = request.form['inputFirewallOption']
            inputTCPOption = request.form['inputTCPOption']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputType:
                flash('Type is required!')
            elif not inputSecurityBanner:
                flash('Security banner is required!')
            elif not inputNewEnableSecret:
                flash('New enable secret is required!')
            elif not (6 <= len(inputNewEnableSecret) <= 25):
                flash('Secret length must be between 6 and 25 characters!')
            elif not inputConfirmNewEnableSecret:
                flash('Confirm new enable secret is required!')
            elif inputNewEnableSecret != inputConfirmNewEnableSecret:
                flash('Enable secrets differ!')
            elif not inputNewEnablePassword:
                flash('New enable password is required!')
            elif inputNewEnablePassword == inputNewEnableSecret:
                flash("Choose a password that's different from secret!")
            elif not inputConfirmNewEnablePassword:
                flash('Confirm new enable password is required!')
            elif inputNewEnablePassword != inputConfirmNewEnablePassword:
                flash('Enable passwords differ!')
            elif not inputLocalUsername:
                flash('Local username is required!')
            elif not inputLocalPassword:
                flash('Local password is required!')
            elif not (6 <= len(inputLocalPassword) <= 25):
                flash('Local password length must be between 6 and 25 characters!')
            elif not inputConfirmLocalPassword:
                flash('Confirm local password is required!')
            elif inputLocalPassword != inputConfirmLocalPassword:
                flash('Local passwords differ!')
            elif not inputBlockingPeriod:
                flash('Blocking period is required!')
            elif not (1 <= len(inputBlockingPeriod) <= 32767):
                flash('Blocking period is not between 1 and 32767!')
            elif not inputLoginFailures:
                flash('Login failures is required!')
            elif not (1 <= len(inputLoginFailures) <= 32767):
                flash('Login failures is not between 1 and 32767!')
            elif not inputTimePeriod:
                flash('Time period is required!')
            elif not (1 <= len(inputTimePeriod) <= 32767):
                flash('Time period is not between 1 and 32767!')
            elif not inputSSHOption:
                flash('SSH option is required!')
            elif not inputHostname:
                flash('Hostname is required!')
            elif not inputDomainName:
                flash('Domain-name is required!')
            elif not inputFirewallOption:
                flash('Firewall option is required!')
            elif not inputTCPOption:
                flash('TCP option is required!')
            else:
                inputSecurityBanner = 'k' + inputSecurityBanner + 'k'
                vars_array = []
                vars_array.extend(
                    [inputType, inputSecurityBanner, inputNewEnableSecret, inputNewEnablePassword, inputLocalUsername,
                     inputLocalPassword, inputBlockingPeriod, inputLoginFailures, inputTimePeriod, inputSSHOption,
                     inputHostname, inputDomainName, inputFirewallOption, inputTCPOption])
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    output = autosecure.do_autosecure(devices_ip, devices_ostype, devices_username, inputPassword,
                                                      inputEnablePassword, vars_array)
                    os.remove(inputInventory)
                    flash(output)
                    return redirect(request.url)


        elif template_type == "IPSG":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputType = request.form['inputType']
            inputIpAddress = request.form['inputIpAddress']
            inputMacAddress = request.form['inputMacAddress']
            inputVlan = request.form['inputVlan']
            inputInterface = request.form['inputInterface']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputInterface:
                flash('Interface is required!')
            elif not inputIpAddress:
                flash('Ip address is required!')
            elif not inputMacAddress:
                flash('MAC address is required!')
            elif not inputVlan:
                flash('VLAN is required!')
            elif validate_ip_address(inputIpAddress) == False:
                flash('That is not a valid IP address!')
            elif validate_mac_address(inputMacAddress) == False:
                flash('That is not a valid MAC address!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                elif napalm_retrieve_info.check_interface(inputInterface, devices_ip, devices_ostype, devices_username,
                                                          inputPassword, inputEnablePassword) == 0:
                    flash("The interface you entered is not present in all of the devices you selected!")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    output = napalm_ip_source_guard.do_ipsg(devices_ip, devices_ostype, devices_username, inputPassword,
                                                            inputEnablePassword, inputType, inputIpAddress,
                                                            inputMacAddress, inputVlan, inputInterface)
                    os.remove(inputInventory)
                    flash(output)
                    return redirect(request.url)

        elif template_type == "SecureBoot":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    output = secure_boot.do_secureboot(devices_ip, devices_ostype, devices_username, inputPassword,
                                                       inputEnablePassword, "archive_router_config")
                    os.remove(inputInventory)
                    flash(output)
                    return redirect(request.url)

        elif template_type == "DHCPSnooping":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputVlans = request.form['inputVLANs']
            inputTrustedInterfaces = request.form['inputTrustedInterfaces']
            inputUntrustedLimit = request.form['inputUntrustedLimit']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputTrustedInterfaces:
                flash('Interfaces are required!')
            elif not inputVlans:
                flash('VLANs are required!')
            elif not inputUntrustedLimit:
                flash('Limit is required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                    return redirect(request.url)
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    VLANs = split_string(inputVlans)
                    for inputVLAN in VLANs:
                        if check_range(inputVLAN) == 0:
                            os.remove(inputInventory)
                            flash("The VLANs are not entered correctly, check the spelling!")
                            return redirect(request.url)
                    trusted_interfaces = split_string(inputTrustedInterfaces)
                    ok_interfaces = 1
                    for inputInterface in trusted_interfaces:
                        if napalm_retrieve_info.check_interface(inputInterface, devices_ip, devices_ostype,
                                                                devices_username,
                                                                inputPassword, inputEnablePassword) == 0:
                            os.remove(inputInventory)
                            os.remove(inputInventory)
                            ok_interfaces = 0
                            flash(
                                "The interface you entered is not present in all of the devices you selected or you didn't write the interfaces string right!")
                            return redirect(request.url)
                    if ok_interfaces == 1:
                        output = dhcp_snooping.do_dhcp_snooping(devices_ip, devices_ostype, devices_username,
                                                                inputPassword,
                                                                inputEnablePassword, VLANs, trusted_interfaces,
                                                                inputUntrustedLimit)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)

        elif template_type == "DAI":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputVLANs = request.form['inputVLANs']
            inputUntrustedInterfaces = request.form['inputUntrustedInterfaces']
            inputTrustedInterfaces = request.form['inputTrustedInterfaces']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                VLANs = split_string(inputVLANs)
                for inputVLAN in VLANs:
                    if check_range(inputVLAN) == 0:
                        flash("The VLANs are not entered correctly, check the spelling!")
                        return redirect(request.url)
                trustedInterfaces = split_string(inputTrustedInterfaces)
                untrustedInterfaces = split_string(inputUntrustedInterfaces)
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                ok = 1
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    ok = 0
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                for inputInterface in trustedInterfaces:
                    if napalm_retrieve_info.check_interface(inputInterface, devices_ip, devices_ostype,
                                                            devices_username, inputPassword,
                                                            inputEnablePassword) == 0:
                        ok = 0
                        flash(
                            "The trusted interface you entered is not present in all of the devices you selected!")
                for inputInterface in untrustedInterfaces:
                    if napalm_retrieve_info.check_interface(inputInterface, devices_ip, devices_ostype,
                                                            devices_username, inputPassword,
                                                            inputEnablePassword) == 0:
                        ok = 0
                        flash(
                            "The untrusted interface you entered is not present in all of the devices you selected!")
                if ok == 1:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    output = dai.dai(devices_ip, devices_ostype, devices_username, inputPassword,
                                     inputEnablePassword, VLANs, trustedInterfaces, untrustedInterfaces)
                    os.remove(inputInventory)
                    flash(output)
                    return redirect(request.url)

        elif template_type == "Copy":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputTargetHostname = request.form['inputTargetHostname']
            inputType = request.form['inputType']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputTargetHostname:
                flash('Target hostname is required!')
            elif not inputType:
                flash('Type is required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    output = copy_files_frommaintarget.copy_from_device_to_devices(inputTargetHostname,
                                                                                   devices_hostname, inputType)
                    os.remove(inputInventory)
                    flash(output)
                    return redirect(request.url)

        elif template_type == "Hostnames":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    # run playbook here
                    play_path = scripts_path + 'set_hostnames.yaml'
                    ansible_cmd = "ansible-playbook -i {0} {2} --extra-vars \"variable_host={1}\"".format(
                        inputInventory, inputDevices, play_path)
                    # to run this cmd

                    output = os.popen(ansible_cmd).read()
                    os.remove(inputInventory)
                    flash(output)
                    return redirect(request.url)

        elif template_type == "DomainName":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputDomainName = request.form['inputDomainName']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputDomainName:
                flash('Domain-name is required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    # run playbook here
                    play_path = scripts_path + 'set_domain_name.yaml'
                    ansible_cmd = "ansible-playbook -i {0} {3} --extra-vars \"variable_host={1} domain_name=\'{2}\'\"".format(
                        inputInventory, inputDevices, inputDomainName, play_path)
                    # to run this cmd

                    output = os.popen(ansible_cmd).read()
                    flash(output)
                    os.remove(inputInventory)
                    # flash(ansible_cmd)
                    return redirect(request.url)

        elif template_type == "Banners":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputMOTDBanner = request.form['inputMOTDBanner']
            inputLoginBanner = request.form['inputLoginBanner']
            inputExecBanner = request.form['inputExecBanner']
            inputIncomingBanner = request.form['inputIncomingBanner']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputMOTDBanner:
                flash('MOTD banner is required!')
            elif not inputLoginBanner:
                flash('Login banner is required!')
            elif not inputExecBanner:
                flash('Exec banner is required!')
            elif not inputIncomingBanner:
                flash('Incoming banner is required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    # run playbook here
                    # motd
                    if inputMOTDBanner == "default":
                        motd_tag = "default_motd"
                        motd_state = "present"
                        path = 'templates/myscripts/banners/default_motd'
                        CONFIG_PATH = os.path.join(ROOT_DIR, path)
                        text_file = open(CONFIG_PATH, "r")

                        # read whole file to a string
                        data = text_file.read()

                        # close file
                        text_file.close()
                        inputMOTDBanner = data
                    elif inputMOTDBanner == "not to set":
                        motd_tag = "motd"
                        motd_state = "absent"
                        inputMOTDBanner = ""
                    else:
                        motd_tag = "motd"
                        motd_state = "present"

                    # login
                    if inputLoginBanner == "default":
                        login_tag = "default_login"
                        login_state = "present"
                        path = 'templates/myscripts/banners/default_login'
                        CONFIG_PATH = os.path.join(ROOT_DIR, path)
                        text_file = open(CONFIG_PATH, "r")

                        # read whole file to a string
                        data = text_file.read()

                        # close file
                        text_file.close()
                        inputLoginBanner = data
                    elif inputLoginBanner == "not to set":
                        login_tag = "login"
                        login_state = "absent"
                        inputLoginBanner = ""
                    else:
                        login_tag = "login"
                        login_state = "present"

                    # exec
                    if inputExecBanner == "default":
                        exec_tag = "default_exec"
                        exec_state = "present"
                        path = 'templates/myscripts/banners/default_exec'
                        CONFIG_PATH = os.path.join(ROOT_DIR, path)
                        text_file = open(CONFIG_PATH, "r")

                        # read whole file to a string
                        data = text_file.read()

                        # close file
                        text_file.close()
                        inputExecBanner = data
                    elif inputExecBanner == "not to set":
                        exec_tag = "exec"
                        exec_state = "absent"
                        inputExecBanner = ""
                    else:
                        exec_tag = "exec"
                        exec_state = "present"

                    # incoming
                    if inputIncomingBanner == "default":
                        incoming_tag = "default_incoming"
                        incoming_state = "present"
                        path = 'templates/myscripts/banners/default_incoming'
                        CONFIG_PATH = os.path.join(ROOT_DIR, path)
                        text_file = open(CONFIG_PATH, "r")

                        # read whole file to a string
                        data = text_file.read()

                        # close file
                        text_file.close()
                        inputIncomingBanner = data
                    elif inputIncomingBanner == "not to set":
                        incoming_tag = "incoming"
                        incoming_state = "absent"
                        inputIncomingBanner = ""
                    else:
                        incoming_tag = "incoming"
                        incoming_state = "present"

                    play_path = scripts_path + 'ios_banner_config.yaml'
                    ansible_cmd = "ansible-playbook -i {0} {14} --tags \"{2},{3},{4},{5}\" --extra-vars \"variable_host={1} motd_banner=\'{6}\' motd_state=\'{7}\' login_banner=\'{8}\' login_state=\'{9}\' exec_banner=\'{10}\' exec_state=\'{11}\' incoming_banner=\'{12}\' incoming_state=\'{13}\'\"".format(
                        inputInventory, inputDevices, motd_tag, login_tag, exec_tag, incoming_tag, inputMOTDBanner,
                        motd_state, inputLoginBanner, login_state, inputExecBanner, exec_state, inputIncomingBanner,
                        incoming_state, play_path)
                    # to run this cmd
                    output = os.popen(ansible_cmd).read()
                    os.remove(inputInventory)
                    flash(output)
                    # flash(ansible_cmd)
                    return redirect(request.url)

        elif template_type == "Syslog":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputSyslogServer = request.form['inputSyslogServer']
            inputTimestamps = request.form['inputTimestamps']
            inputDatetime = request.form['inputDatetime']
            inputFacility = request.form['inputFacility']
            inputTrap = request.form['inputTrap']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputSyslogServer:
                flash('Syslog server is required!')
            elif validate_ip_address(inputSyslogServer) == False:
                flash('That is not a valid IP address for syslog server!')
            elif not inputTimestamps:
                flash('Timestamp is required!')
            elif not inputDatetime:
                flash('Datetime is required!')
            elif not inputFacility:
                flash('Facility is required!')
            elif not inputTrap:
                flash('Trap is required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    # run playbook here
                    play_path = scripts_path + 'syslog_config.yaml'
                    ansible_cmd = "ansible-playbook -i {0} {7} --tags \"set_syslog_server,set_facility,set_trap_level\" --extra-vars \"variable_host={1} timestamps_type=\'{2}\' datetime_choice=\'{3}\' syslog_server=\'{4}\' facility_type=\'{5}\' trap_level=\'{6}\'\"".format(
                        inputInventory, inputDevices, inputTimestamps, inputDatetime, inputSyslogServer, inputFacility,
                        inputTrap, play_path)
                    # to run this cmd
                    output = os.popen(ansible_cmd).read()
                    os.remove(inputInventory)
                    flash(output)
                    # flash(ansible_cmd)
                    return redirect(request.url)

        elif template_type == "Save":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    # run playbook here
                    play_path = scripts_path + 'save_config.yaml'
                    ansible_cmd = "ansible-playbook -i {0} {2} --tags \"save_config\" --extra-vars \"variable_host={1}\"".format(
                        inputInventory, inputDevices, play_path)
                    # to run this cmd
                    output = os.popen(ansible_cmd).read()
                    os.remove(inputInventory)
                    flash(output)
                    # flash(ansible_cmd)
                    return redirect(request.url)


        # nu merge pt Cisco 7200, doar pt Cisco IOSv, pentru ca 7200 nu are flash0
        elif template_type == "LoadBackup":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    # run playbook here
                    possible_error = netmiko_before_loadbackup.before_loading(devices_ip, devices_ostype,
                                                                              devices_username, inputPassword,
                                                                              inputEnablePassword)
                    if possible_error != 1:
                        os.remove(inputInventory)
                        flash(possible_error)
                        return redirect(request.url)
                    else:
                        # transfer backup files
                        possible_error2 = netmiko_scp.check_scp(inputInventory, inputDevices, devices_ip,
                                                                devices_ostype,
                                                                devices_username, inputPassword, inputEnablePassword)
                        if possible_error2 == None:
                            play_path = scripts_path + 'ios_load_config.yaml'
                            ansible_cmd = "ansible-playbook -i {0} {2} --extra-vars \"variable_host={1}\"".format(
                                inputInventory, inputDevices, play_path)
                            # to run this cmd

                            output = os.popen(ansible_cmd).read()
                            flash(output)
                            os.remove(inputInventory)
                            # flash(ansible_cmd)
                            return redirect(request.url)
                        elif "Oops" in possible_error2 or "Connection Refused" in possible_error2:
                            os.remove(inputInventory)
                            flash("The transfer did not succeed for all of the files!")
                            return redirect(request.url)

        elif template_type == "Backup":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    # run playbook here
                    play_path = scripts_path + 'ios_config_backup.yaml'
                    ansible_cmd = "ansible-playbook -i {0} {2} --extra-vars \"variable_host={1}\"".format(
                        inputInventory, inputDevices, play_path)
                    # to run this cmd
                    output = os.popen(ansible_cmd).read()
                    os.remove(inputInventory)
                    flash(output)
                    # flash(ansible_cmd)
                    return redirect(request.url)

        elif template_type == "SNMPv3":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputSNMPOption = request.form['inputSNMPOption']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputSNMPOption:
                flash('SNMPv3 option is required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    # run playbook here
                    ansible_cmd = ""
                    if inputSNMPOption == "gather":
                        play_path = scripts_path + 'ios_snmpv3_gatherfacts.yaml'
                        ansible_cmd = "ansible-playbook -i {0} {2} --extra-vars \"variable_host={1}\"".format(
                            inputInventory, inputDevices, play_path)
                    elif inputSNMPOption == "delete":
                        play_path = scripts_path + 'ios_snmpv3_deleteall.yaml'
                        ansible_cmd = "ansible-playbook -i {0} {2} --extra-vars \"variable_host={1}\"".format(
                            inputInventory, inputDevices, play_path)
                    elif inputSNMPOption == "load":
                        inputLoadOption = request.form['inputLoadOption']
                        play_path = scripts_path + 'ios_snmpv3_config.yaml'
                        ansible_cmd = "ansible-playbook -i {0} {3} --extra-vars \"variable_host={1} state=\"{2}\"\"".format(
                            inputInventory, inputDevices, inputLoadOption, play_path)
                    # to run this cmd
                    output = os.popen(ansible_cmd).read()
                    os.remove(inputInventory)
                    flash(output)
                    # flash(ansible_cmd)
                    return redirect(request.url)

        elif template_type == "ACL":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputACLOption = request.form['inputACLOption']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    # run playbook here
                    ansible_cmd = ""
                    if inputACLOption == "gather":
                        play_path = scripts_path + 'ios_acl_gatherfacts.yaml'
                        ansible_cmd = "ansible-playbook -i {0} {2} --extra-vars \"variable_host={1}\"".format(
                            inputInventory, inputDevices, play_path)
                    elif inputACLOption == "deleteall":
                        play_path = scripts_path + 'ios_acl_deleteall.yaml'
                        ansible_cmd = "ansible-playbook -i {0} {2} --extra-vars \"variable_host={1}\"".format(
                            inputInventory, inputDevices, play_path)
                    elif inputACLOption == "load":
                        inputLoadOption = request.form['inputLoadOption']
                        play_path = scripts_path + 'ios_acl_config.yaml'
                        ansible_cmd = "ansible-playbook -i {0} {3} --extra-vars \"variable_host={1} state=\"{2}\"\"".format(
                            inputInventory, inputDevices, inputLoadOption, play_path)
                    elif inputACLOption == "deleteafi":
                        inputAFI = request.form['inputAFI']
                        play_path = scripts_path + 'ios_acl_deleteafi.yaml'
                        ansible_cmd = "ansible-playbook -i {0} {3} --extra-vars \"variable_host={1} afi_type=\"{2}\"\"".format(
                            inputInventory, inputDevices, inputAFI, play_path)
                    # to run this cmd
                    # output = os.popen(ansible_cmd).read()
                    # os.remove(inputInventory)
                    # flash(output)
                    flash(ansible_cmd)
                    return redirect(request.url)

        elif template_type == "STP":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            vars_array = []

            inv_path = 'templates/myscripts/inventories/' + inputInventory
            original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
            devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                original_inv_path, inputDevices)
            if ((devices_username != inputUsername) or (
                    sha256_crypt.verify(inputPassword, devices_password) != True) or (
                    sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                flash("These are not the credentials from the inventory file! Please reconfigure the file accordingly.")

            inputType = request.form['inputType']
            if inputType == 'switch_stp':
                inputFeature = request.form['inputFeature']
                if inputFeature == 'backbonefast':
                    vars_array.append(inputFeature + '\n')
                elif inputFeature == 'bridge':
                    vars_array.append(inputFeature + ' assurance' + '\n')
                elif inputFeature == 'etherchannel':
                    vars_array.append(inputFeature + ' guard misconfig' + '\n')
                elif inputFeature == 'extend':
                    vars_array.append(inputFeature + ' system-id' + '\n')
                elif inputFeature == 'logging':
                    vars_array.append(inputFeature + '\n')
                elif inputFeature == 'loopguard':
                    vars_array.append(inputFeature + ' default' + '\n')
                elif inputFeature == 'mode':
                    inputMode = request.form['inputMode']
                    item = inputFeature + ' ' + inputMode + '\n'
                    vars_array.append(item)
                elif inputFeature == 'mst':
                    inputConfigurationOption = request.form['inputConfigurationOption']
                    item = inputFeature
                    if inputConfigurationOption == "Yes config":
                        inputConfigName = request.form['inputConfigName']
                        item = item + ' configuration ' + inputConfigName + '\n'
                        vars_array.append(item)
                        item = inputFeature
                    inputForwardOption = request.form['inputForwardOption']
                    if inputForwardOption == "Yes forward":
                        inputForwardTime = request.form['inputForwardTime']
                        item = item + ' forward-time ' + inputForwardTime + '\n'
                        vars_array.append(item)
                        item = inputFeature
                    inputHelloOption = request.form['inputHelloOption']
                    if inputHelloOption == "Yes hello":
                        inputHelloTime = request.form['inputHelloTime']
                        item = item + ' hello-time ' + inputHelloTime + '\n'
                        vars_array.append(item)
                        item = inputFeature
                    inputMaxAgeOption = request.form['inputMaxAgeOption']
                    if inputMaxAgeOption == "Yes maxage":
                        inputMaxAge = request.form['inputMaxAge']
                        item = item + ' max-age ' + inputMaxAge + '\n'
                        vars_array.append(item)
                        item = inputFeature
                    inputMaxHopsOption = request.form['inputMaxHopsOption']
                    if inputMaxHopsOption == "Yes maxhops":
                        inputMaxHops = request.form['inputMaxHops']
                        item = item + ' max-hops ' + inputMaxHops + '\n'
                        vars_array.append(item)
                        item = inputFeature
                elif inputFeature == 'pathcost':
                    inputPathcost = request.form['inputPathcost']
                    item = inputFeature + ' method ' + inputPathcost + '\n'
                    vars_array.append(item)
                elif inputFeature == 'portfast':
                    inputPortfast = request.form['inputPortfast']
                    if inputPortfast != "default":
                        item = inputFeature + ' ' + inputPortfast + ' default\n'
                    else:
                        item = inputFeature + ' ' + inputPortfast + '\n'
                    vars_array.append(item)
                elif inputFeature == 'transmit':
                    inputTranmsit = request.form['inputTranmsit']
                    item = inputFeature + ' hold-count ' + inputTranmsit + '\n'
                    vars_array.append(item)
                elif inputFeature == 'uplinkfast':
                    inputUplinkfast = request.form['inputUplinkfast']
                    item = inputFeature + ' max-update-rate ' + inputUplinkfast + '\n'
                    vars_array.append(item)
                elif inputFeature == 'vlan':
                    inputVLAN = request.form['inputVLAN']
                    if check_range(inputVLAN) == 0:
                        flash("The VLAN is not a number or it is not a range of numbers!")
                    else:
                        item = inputFeature + ' ' + inputVLAN
                        done = 0
                        inputForwardOption = request.form['inputForwardOption']
                        if inputForwardOption == "Yes forward":
                            inputForwardTime = request.form['inputForwardTime']
                            item = item + ' forward-time ' + inputForwardTime + '\n'
                            vars_array.append(item)
                            done = 1
                            item = inputFeature + ' ' + inputVLAN
                        inputHelloOption = request.form['inputHelloOption']
                        if inputHelloOption == "Yes hello":
                            inputHelloTime = request.form['inputHelloTime']
                            item = item + ' hello-time ' + inputHelloTime + '\n'
                            vars_array.append(item)
                            done = 1
                            item = inputFeature + ' ' + inputVLAN
                        inputMaxAgeOption = request.form['inputMaxAgeOption']
                        if inputMaxAgeOption == "Yes maxage":
                            inputMaxAge = request.form['inputMaxAge']
                            item = item + ' max-age ' + inputMaxAge + '\n'
                            vars_array.append(item)
                            done = 1
                            item = inputFeature + ' ' + inputVLAN
                        inputPriorityOption = request.form['inputPriorityOption']
                        if inputPriorityOption == "Yes priority":
                            inputPriority = request.form['inputPriority']
                            item = item + ' priority ' + inputPriority + '\n'
                            vars_array.append(item)
                            done = 1
                            item = inputFeature + ' ' + inputVLAN
                        inputRootOption = request.form['inputRootOption']
                        if inputRootOption == "Yes root":
                            inputRoot = request.form['inputRoot']
                            item = item + ' root ' + inputRoot + '\n'
                            vars_array.append(item)
                            done = 1
                            item = inputFeature + ' ' + inputVLAN
                        if done == 0:
                            item = item + '\n'
                            vars_array.append(item)

                output = stp.do_stp(devices_ip, devices_ostype, devices_username, inputPassword,
                                    inputEnablePassword, inputType, vars_array)
                flash(output)


            elif inputType == 'interface_stp':
                inputInterface = request.form['inputInterface']
                vars_array.append("interface " + inputInterface + '\n')
                inputFeature = request.form['inputFeature']
                inputFeature = inputFeature[:-1]
                item = inputFeature
                if inputFeature == "bpdufilter":
                    inputBPDUFilter = request.form['inputBPDUFilter']
                    vars_array.append(inputFeature + ' ' + inputBPDUFilter + '\n')
                elif inputFeature == "bpduguard":
                    inputBPDUGuard = request.form['inputBPDUGuard']
                    vars_array.append(inputFeature + ' ' + inputBPDUGuard + '\n')
                elif inputFeature == "cost":
                    inputCost = request.form['inputCost']
                    vars_array.append(inputFeature + ' ' + inputCost + '\n')
                elif inputFeature == "guard":
                    inputGuard = request.form['inputGuard']
                    vars_array.append(inputFeature + ' ' + inputGuard + '\n')
                elif inputFeature == "link-type":
                    inputLinktype = request.form['inputLinktype']
                    vars_array.append(inputFeature + ' ' + inputLinktype + '\n')
                elif inputFeature == "mst":
                    inputInterfaceMST = request.form['inputInterfaceMST']
                    if inputInterfaceMST == 'instance cost':
                        inputIntMST = request.form['inputIntMST']
                        inputIntMstCost = request.form['inputIntMstCost']
                        vars_array.append(inputFeature + ' ' + inputIntMST + ' cost ' + inputIntMstCost + '\n')
                    elif inputInterfaceMST == 'instance port-priority':
                        inputIntMST = request.form['inputIntMST']
                        if check_range(inputIntMST) == 0:
                            flash("This is not a valid Interface MST range!")
                        else:
                            inputIntMSTPortpriority = request.form['inputIntMSTPortpriority']
                            vars_array.append(
                                inputFeature + ' ' + inputIntMST + ' port-priority ' + inputIntMSTPortpriority + '\n')
                    else:
                        vars_array.append(inputFeature + ' ' + inputInterfaceMST + '\n')
                elif inputFeature == "port-priority":
                    inputPortpriority = request.form['inputPortpriority']
                    vars_array.append(inputFeature + ' ' + inputPortpriority + '\n')
                elif inputFeature == "portfast":
                    inputInterfacePortfast = request.form['inputInterfacePortfast']
                    vars_array.append(inputFeature + ' ' + inputInterfacePortfast + '\n')

                output = stp.do_stp(devices_ip, devices_ostype, devices_username, inputPassword, inputEnablePassword,
                                    inputType, vars_array)
                flash(output)

        elif template_type == "NTP":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputNTPServer = request.form['inputNTPServer']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputNTPServer:
                flash('NTP server option is required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    # run playbook here
                    ansible_cmd = ""
                    if inputNTPServer == 'Yes server':
                        # get time format
                        server_now = datetime.now()
                        day = server_now.strftime("%d")
                        year = server_now.strftime("%Y")
                        month = server_now.strftime("%b").lower()
                        time = server_now.strftime("%H:%M:%S")
                        tag = "ntp_server"

                        play_path = scripts_path + 'ntp_config.yaml'
                        ansible_cmd = "ansible-playbook -i {0} {7} -t \"{6}\" --extra-vars \"variable_host={1} time=\"{2}\" day=\"{3}\" month=\"{4}\" year=\"{5}\"\"".format(
                            inputInventory, inputDevices, time, day, month, year, tag, play_path)
                    elif inputNTPServer == 'No server':
                        inputNTPClient = request.form['inputNTPClient']
                        if inputNTPClient == 'Yes client':
                            inputClientServer = request.form['inputClientServer']
                            if validate_ip_address(inputClientServer) == True:
                                tag = "ntp_client"
                                play_path = scripts_path + 'ntp_config.yaml'
                                ansible_cmd = "ansible-playbook -i {0} {4} -t \"{3}\" --extra-vars \"variable_host={1} server_ip=\"{2}\"\"".format(
                                    inputInventory, inputDevices, inputClientServer, tag, play_path)
                                flash(ansible_cmd)
                            else:
                                os.remove(inputInventory)
                                flash("This is not a valid IP address!")
                        else:
                            os.remove(inputInventory)
                            flash("Choose an option please!")
                    # to run this cmd
                    output = os.popen(ansible_cmd).read()
                    os.remove(inputInventory)
                    flash(output)
                    # flash(ansible_cmd)
                    return redirect(request.url)

        elif template_type == "Users":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputUserType = request.form['inputUserType']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputUserType:
                flash('User type is required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    ansible_cmd = ""
                    if inputUserType == "create_new_user_password":
                        inputUser = request.form['inputUser']
                        inputPasswordType = request.form['inputPasswordType']
                        inputUserPassword = request.form['inputUserPassword']
                        inputConfirmUserPassword = request.form['inputConfirmUserPassword']
                        if inputUserPassword != inputConfirmUserPassword:
                            os.remove(inputInventory)
                            flash("The passwords to be set do not match!")
                        else:
                            play_path = scripts_path + 'users.yaml'
                            ansible_cmd = "ansible-playbook -i {0} {5} --tags \"create_new_user_password\" --extra-vars \"variable_host={1} new_user=\'{2}\' password_type=\'{3}\' new_password=\'{4}\'\"".format(
                                inputInventory, inputDevices, inputUser, inputPasswordType, inputPassword, play_path)
                    elif inputUserType == "remove_all_users":
                        play_path = scripts_path + 'users.yaml'
                        ansible_cmd = "ansible-playbook -i {0} {2} --tags \"remove_all_users\" --extra-vars \"variable_host={1}\"".format(
                            inputInventory, inputDevices, play_path)
                    elif inputUserType == "remove_user":
                        play_path = scripts_path + 'users.yaml'
                        inputUser = request.form['inputUser']
                        ansible_cmd = "ansible-playbook -i {0} {3} --tags \"remove_user\" --extra-vars \"variable_host={1} to_remove_user=\'{2}\'\"".format(
                            inputInventory, inputDevices, inputUser, play_path)
                    elif inputUserType == "set_user_privilege":
                        play_path = scripts_path + 'users.yaml'
                        inputUser = request.form['inputUser']
                        inputPrivilege = request.form['inputPrivilege']
                        ansible_cmd = "ansible-playbook -i {0} {4} --tags \"set_user_privilege\" --extra-vars \"variable_host={1} user=\'{2}\' privilege=\'{3}\'\"".format(
                            inputInventory, inputDevices, inputUser, inputPrivilege, play_path)
                    elif inputUserType == "set_new_password":
                        inputUser = request.form['inputUser']
                        inputPasswordType = request.form['inputPasswordType']
                        inputUserPassword = request.form['inputUserPassword']
                        inputConfirmUserPassword = request.form['inputConfirmUserPassword']
                        if inputUserPassword != inputConfirmUserPassword:
                            os.remove(inputInventory)
                            flash("The passwords to be set do not match!")
                        else:
                            play_path = scripts_path + 'users.yaml'
                            ansible_cmd = "ansible-playbook -i {0} {5} --tags \"set_new_password\" --extra-vars \"variable_host={1} user=\'{2}\' password_type=\'{3}\' new_password=\'{4}\'\"".format(
                                inputInventory, inputDevices, inputUser, inputPasswordType, inputPassword, play_path)

                    # to run this cmd
                    output = os.popen(ansible_cmd).read()
                    os.remove(inputInventory)
                    flash(output)
                    # flash(ansible_cmd)
                    return redirect(request.url)

        elif template_type == "TFTP":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputTFTPServer = request.form['inputTFTPServer']
            inputTFTPOption = request.form['inputTFTPOption']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputTFTPServer:
                flash('TFTP server is required!')
            elif validate_ip_address(inputTFTPServer) == False:
                flash('That is not a valid IP address for TFTP server!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    my_hostnames, my_ips, my_src_files, my_dest_files = netmiko_get_devices_array.get_device_src_dest_transfer_files(
                        inputInventory, inputDevices)
                    if len(my_hostnames) == len(my_ips) == len(my_src_files) == len(my_dest_files):
                        # to run this cmd
                        output = tftp_transfer.do_tftp(devices_ip, devices_ostype, devices_username, inputPassword,
                                                       inputEnablePassword, inputTFTPOption, inputTFTPServer,
                                                       my_src_files, my_dest_files)
                        # flash(output)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    else:
                        os.remove(inputInventory)
                        flash("This inventory files' devices are missing something! Check it again before submitting!")

        elif template_type == "FTP":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputFTPServer = request.form['inputFTPServer']
            inputFTPOption = request.form['inputFTPOption']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputFTPServer:
                flash('FTP server is required!')
            elif validate_ip_address(inputFTPServer) == False:
                flash('That is not a valid IP address for TFTP server!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    my_hostnames, my_ips, my_src_files, my_dest_files = netmiko_get_devices_array.get_device_src_dest_transfer_files(
                        inputInventory, inputDevices)
                    if len(my_hostnames) == len(my_ips) == len(my_src_files) == len(my_dest_files):
                        # to run this cmd
                        if inputFTPOption == "Set credentials":
                            inputFTPUsername = request.form['inputFTPUsername']
                            inputFTPPassword = request.form['inputFTPPassword']
                            output = setup_ftp.do_ftp(devices_ip, devices_ostype, devices_username, inputPassword,
                                                      inputEnablePassword, inputFTPOption, inputFTPServer,
                                                      inputFTPUsername, inputFTPPassword)
                        else:
                            output = setup_ftp.do_ftp(devices_ip, devices_ostype, devices_username, inputPassword,
                                                      inputEnablePassword, inputFTPOption, inputFTPServer, my_src_files,
                                                      my_dest_files)
                        # flash(output)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    else:
                        os.remove(inputInventory)
                        flash("This inventory files' devices are missing something! Check it again before submitting!")
                        return redirect(request.url)

        elif template_type == "OSPF":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputType = request.form['inputType']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputType:
                flash('Type is required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    my_hostnames, my_ips, my_src_files, my_dest_files = netmiko_get_devices_array.get_device_src_dest_transfer_files(
                        inputInventory, inputDevices)
                    if inputType == "enable_ospf":
                        inputProcessID = request.form['inputProcessID']
                        inputNetworkIP = request.form['inputNetworkIP']
                        inputWildcardMask = request.form['inputWildcardMask']
                        inputAreaID = request.form['inputAreaID']
                        if validate_ip_address(inputNetworkIP) == False:
                            os.remove(inputInventory)
                            flash('That is not a valid IP address for network!')
                        elif validate_ip_address(inputWildcardMask) == False:
                            os.remove(inputInventory)
                            flash('That is not a valid IP address for wildcard mask!')
                        else:
                            # cmd here
                            vars_array = []
                            vars_array.extend([inputProcessID, inputNetworkIP, inputWildcardMask, inputAreaID])
                            output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username, inputPassword,
                                                          inputEnablePassword, inputType, vars_array)
                            os.remove(inputInventory)
                            flash(output)
                            return redirect(request.url)
                    elif inputType == "area_parameters":
                        inputProcessID = request.form['inputProcessID']
                        inputAreaID = request.form['inputAreaID']
                        inputCostValue = request.form['inputCostValue']
                        # cmd here
                        vars_array = []
                        vars_array.extend([inputProcessID, inputAreaID, inputCostValue])
                        output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username, inputPassword,
                                                      inputEnablePassword, inputType, vars_array)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    elif inputType == "blocking_ospf_lsa_flooding":
                        inputInterface = request.form['inputInterface']
                        # cmd here
                        vars_array = []
                        vars_array.append(inputInterface)
                        output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username, inputPassword,
                                                      inputEnablePassword, inputType, vars_array)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    elif inputType == "blocking_ospf_lsa_flooding_point_to_multipoint":
                        inputProcessID = request.form['inputProcessID']
                        inputNeighborIP = request.form['inputNeighborIP']
                        if validate_ip_address(inputNeighborIP) == False:
                            os.remove(inputInventory)
                            flash('That is not a valid IP address for neighbor!')
                        else:
                            # cmd here
                            vars_array = []
                            vars_array.extend([inputProcessID, inputNeighborIP])
                            output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username,
                                                          inputPassword,
                                                          inputEnablePassword, inputType, vars_array)
                            os.remove(inputInventory)
                            flash(output)
                            return redirect(request.url)
                    elif inputType == "changing_ospf_administrative_distances":
                        inputProcessID = request.form['inputProcessID']
                        inputRoutesType = request.form['inputRoutesType']
                        inputDistanceValue = request.form['inputDistanceValue']
                        # cmd here
                        vars_array = []
                        vars_array.extend([inputProcessID, inputRoutesType, inputDistanceValue])
                        output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username,
                                                      inputPassword,
                                                      inputEnablePassword, inputType, vars_array)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    elif inputType == "changing_the_lsa_group_pacing_interval":
                        inputProcessID = request.form['inputProcessID']
                        inputSeconds = request.form['inputSeconds']
                        # cmd here
                        vars_array = []
                        vars_array.extend([inputProcessID, inputSeconds])
                        output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username,
                                                      inputPassword,
                                                      inputEnablePassword, inputType, vars_array)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    elif inputType == "configure_lookup_of_dns_names":
                        # cmd here
                        vars_array = []
                        output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username,
                                                      inputPassword,
                                                      inputEnablePassword, inputType, vars_array)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    elif inputType == "configure_ospf_over_on_demand_circuits":
                        inputProcessID = request.form['inputProcessID']
                        inputInterface = request.form['inputInterface']
                        # cmd here
                        vars_array = []
                        vars_array.extend([inputProcessID, inputInterface])
                        output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username,
                                                      inputPassword,
                                                      inputEnablePassword, inputType, vars_array)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    elif inputType == "configure_route_calculation_timers":
                        inputProcessID = request.form['inputProcessID']
                        inputSPFStart = request.form['inputSPFStart']
                        inputSPFHold = request.form['inputSPFHold']
                        inputSPFMaxwait = request.form['inputSPFMaxwait']
                        # cmd here
                        vars_array = []
                        vars_array.extend([inputProcessID, inputSPFStart, inputSPFHold, inputSPFMaxwait])
                        output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username,
                                                      inputPassword,
                                                      inputEnablePassword, inputType, vars_array)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    elif inputType == "controlling_default_metrics":
                        inputProcessID = request.form['inputProcessID']
                        inputRefBW = request.form['inputRefBW']
                        # cmd here
                        vars_array = []
                        vars_array.extend([inputProcessID, inputRefBW])
                        output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username,
                                                      inputPassword,
                                                      inputEnablePassword, inputType, vars_array)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    elif inputType == "generating_default_route" or inputType == "rfc_1587":
                        inputProcessID = request.form['inputProcessID']
                        # cmd here
                        vars_array = []
                        vars_array.append(inputProcessID)
                        output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username,
                                                      inputPassword,
                                                      inputEnablePassword, inputType, vars_array)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    elif inputType == "interface_parameters":
                        inputInterface = request.form['inputInterface']
                        inputIntCostValue = request.form['inputIntCostValue']
                        inputTransmitSeconds = request.form['inputTransmitSeconds']
                        inputRetransmitSeconds = request.form['inputRetransmitSeconds']
                        inputPriority = request.form['inputPriority']
                        inputHelloInterval = request.form['inputHelloInterval']
                        inputDeadInterval = request.form['inputDeadInterval']
                        inputAuthKey = request.form['inputAuthKey']
                        inputKeyID = request.form['inputKeyID']
                        inputMD5Key = request.form['inputMD5Key']
                        inputAuthenticationOption = request.form['inputAuthenticationOption']
                        # cmd here
                        vars_array = []
                        vars_array.extend(
                            [inputInterface, inputIntCostValue, inputRetransmitSeconds, inputTransmitSeconds,
                             inputPriority, inputHelloInterval, inputDeadInterval, inputAuthKey, inputKeyID,
                             inputMD5Key, inputAuthenticationOption])
                        output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username,
                                                      inputPassword,
                                                      inputEnablePassword, inputType, vars_array)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    elif inputType == "nssa_abr_as_a_forced_nssa_translator":
                        inputProcessID = request.form['inputProcessID']
                        inputAreaID = request.form['inputAreaID']
                        # cmd here
                        vars_array = []
                        vars_array.extend([inputProcessID, inputAreaID])
                        output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username,
                                                      inputPassword,
                                                      inputEnablePassword, inputType, vars_array)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    elif inputType == "point_to_multipoint_broadcast" or inputType == "point_to_multipoint_nonbroadcast":
                        inputInterface = request.form['inputInterface']
                        inputProcessID = request.form['inputProcessID']
                        inputCostValues = request.form['inputCostValues']
                        inputNeighborIPs = request.form['inputNeighborIPs']
                        ipAddresses = split_string(inputNeighborIPs)
                        costValues = split_string(inputCostValues)
                        for ipaddress in ipAddresses:
                            if not validate_ip_address(ipaddress):
                                os.remove(inputInventory)
                                flash(
                                    'That is not a valid IP address for neighbor or you did not write the string correctly! Read the description again.')
                                return redirect(request.url)
                        for costValue in costValues:
                            if not check_range(costValue) or not 1 < costValue < 65535:
                                os.remove(inputInventory)
                                flash(
                                    'The cost values string is not valid or you did not write the string correctly! Read the description again.')
                                return redirect(request.url)

                        # cmd here
                        vars_array = []
                        vars_array.extend([inputInterface, inputProcessID, ipAddresses, costValues])
                        output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username,
                                                      inputPassword,
                                                      inputEnablePassword, inputType, vars_array)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)
                    elif inputType == "reducing_lsa_flooding":
                        inputInterface = request.form['inputInterface']
                        # cmd here
                        vars_array = []
                        vars_array.append(inputInterface)
                        output = netmiko_ospf.do_ospf(devices_ip, devices_ostype, devices_username,
                                                      inputPassword,
                                                      inputEnablePassword, inputType, vars_array)
                        os.remove(inputInventory)
                        flash(output)
                        return redirect(request.url)

        elif template_type == "VTYconsole":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputType = request.form['inputType']
            inputFeature = request.form['inputFeature']
            inputACLNumber = request.form['inputACLNumber']
            ansible_cmd = ""

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputType:
                flash('Type is required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    if inputFeature == "access_list_permit":
                        inputPermit = request.form['inputPermit']
                        permit_list = split_string(inputPermit)
                        for ip in permit_list:
                            if not validate_ip_address(ip):
                                os.remove(inputInventory)
                                flash("Rewrite the permit list of IPs!")
                                return redirect(request.url)
                        if inputType == "vty":
                            play_path = scripts_path + 'vty_config.yaml'
                            ansible_cmd = "ansible-playbook -i {0} {5} --tags \"{2}\" --extra-vars \"variable_host={1} access-list-number=\'{3}\' source_permit=\'{4}\'\"".format(
                                inputInventory, inputDevices, inputFeature, inputACLNumber, permit_list, play_path)
                        else:
                            play_path = scripts_path + 'console.yaml'
                            ansible_cmd = "ansible-playbook -i {0} {5} --tags \"{2}\" --extra-vars \"variable_host={1} access-list-number=\'{3}\' source_permit=\'{4}\'\"".format(
                                inputInventory, inputDevices, inputFeature, inputACLNumber, permit_list, play_path)

                    elif inputFeature == "access_list_deny":
                        inputDeny = request.form['inputDeny']
                        deny_list = split_string(inputDeny)

                        for ip in deny_list:
                            if not validate_ip_address(ip):
                                os.remove(inputInventory)
                                flash("Rewrite the deny list of IPs!")
                                return redirect(request.url)
                        if inputType == "vty":
                            play_path = scripts_path + 'vty_config.yaml'
                            ansible_cmd = "ansible-playbook -i {0} {5} --tags \"{2}\" --extra-vars \"variable_host={1} access_list_number=\'{3}\' source_permit=\'{4}\'\"".format(
                                inputInventory, inputDevices, inputFeature, inputACLNumber, deny_list, play_path)
                        else:
                            play_path = scripts_path + 'console.yaml'
                            ansible_cmd = "ansible-playbook -i {0} {5} --tags \"{2}\" --extra-vars \"variable_host={1} aaccess_list_number=\'{3}\' source_deny=\'{4}\'\"".format(
                                inputInventory, inputDevices, inputFeature, inputACLNumber, deny_list, play_path)

                    elif inputFeature == "inbound_vty_access_vrf_also" or inputFeature == "outbound_vty_access_vrf_also":
                        inputVTYfirstline = request.form['inputVTYfirstline']
                        inputVTYlastline = request.form['inputVTYlastline']
                        if inputVTYfirstline >= inputVTYlastline:
                            flash("Try again, the vty lines are not set right!")
                            os.remove(inputInventory)
                        else:
                            vty_line = 'line vty ' + inputVTYfirstline + ' ' + inputVTYlastline
                            play_path = scripts_path + 'vty_config.yaml'
                            ansible_cmd = "ansible-playbook -i {0} {5} --tags \"{2}\" --extra-vars \"variable_host={1} access_list_number=\'{3}\' vty_lines=\'{4}\'\"".format(
                                inputInventory, inputDevices, inputFeature, inputACLNumber, vty_line, play_path)

                    elif inputFeature == "inbound_console_access_vrf_also" or inputFeature == "outbound_console_access_vrf_also":
                        play_path = scripts_path + 'console.yaml'
                        ansible_cmd = "ansible-playbook -i {0} {4} --tags \"{2}\" --extra-vars \"variable_host={1} access_list_number=\'{3}\'\"".format(
                            inputInventory, inputDevices, inputFeature, inputACLNumber, play_path)

                    # run ansible cmd here
                    if ansible_cmd != "":
                        output = os.popen(ansible_cmd).read()
                        flash(output)
                        # flash(ansible_cmd)
                        os.remove(inputInventory)
                        return redirect(request.url)

        elif template_type == "DTP":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputType = request.form['inputType']
            inputInterface = request.form['inputInterface']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputType:
                flash('Type is required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                    # elif napalm_retrieve_info.check_interface(inputInterface, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password) != 1:
                    #     flash('The connection failed or that is not a valid common interface!')
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    if inputType == "sw_mode_access":
                        inputVLANid = request.form['inputVLANid']
                        play_path = scripts_path + 'dtp.yaml'
                        ansible_cmd = "ansible-playbook -i {0} {5} --tags \"{2}\" --extra-vars \"variable_host={1} interface_number=\'{3}\' vlan_id=\'{4}\'\"".format(
                            inputInventory, inputDevices, inputType, inputInterface, inputVLANid, play_path)
                    else:
                        play_path = scripts_path + 'dtp.yaml'
                        ansible_cmd = "ansible-playbook -i {0} {4} --tags \"{2}\" --extra-vars \"variable_host={1} interface_number=\'{3}\'\"".format(
                            inputInventory, inputDevices, inputType, inputInterface, play_path)

                    output = os.popen(ansible_cmd).read()
                    flash(output)
                    # flash(ansible_cmd)
                    os.remove(inputInventory)
                    return redirect(request.url)

        elif template_type == "DHCPServer":
            inputUsername = request.form['inputUsername']
            inputPassword = request.form['inputPassword']
            inputEnablePassword = request.form['inputEnablePassword']
            inputInventory = request.form['inputInventory']
            inputDevices = request.form['inputDevices']
            inputExcludeFromIP = request.form['inputExcludeFromIP']
            inputExcludeToIP = request.form['inputExcludeToIP']
            inputPool = request.form['inputPool']
            inputNetworkIP = request.form['inputNetworkIP']
            inputNetworkMask = request.form['inputNetworkMask']
            inputLeaseOption = request.form['inputLeaseOption']
            inputDefaultRouter = request.form['inputDefaultRouter']

            if not inputUsername:
                flash('Username is required!')
            elif not inputPassword:
                flash('Password is required!')
            elif not inputEnablePassword:
                flash('Enable password is required!')
            elif not inputDevices:
                flash('Devices are required!')
            elif not inputExcludeFromIP:
                flash('Exclude From IP is required!')
            elif not inputExcludeToIP:
                flash('Exclude To IP is required!')
            elif not inputPool:
                flash('Pool is required!')
            elif not inputNetworkIP:
                flash('Network IP is required!')
            elif not inputNetworkMask:
                flash('Network mask is required!')
            elif not inputLeaseOption:
                flash('Lease option is required!')
            elif not inputDefaultRouter:
                flash('Default Router is required!')
            else:
                inv_path = 'templates/myscripts/inventories/' + inputInventory
                original_inv_path = os.path.join(ROOT_DIR, inv_path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    original_inv_path, inputDevices)
                if ((devices_username != inputUsername) or (
                        sha256_crypt.verify(inputPassword, devices_password) != True) or (
                        sha256_crypt.verify(inputEnablePassword, devices_enable_password) != True)):
                    flash(
                        "These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                    # elif napalm_retrieve_info.check_interface(inputInterface, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password) != 1:
                    #     flash('The connection failed or that is not a valid common interface!')
                else:
                    inputInventory = adjust_file(inputInventory, inputPassword, inputEnablePassword)
                    if inputLeaseOption == "days":
                        inputLease = request.form['inputLease']
                    elif inputLeaseOption == "infinite":
                        inputLease = "infinite"
                    if validate_ip_address(inputExcludeFromIP) == False or validate_ip_address(
                            inputExcludeToIP) == False or validate_ip_address(
                        inputNetworkIP) == False or validate_ip_address(
                        inputNetworkMask) == False or validate_ip_address(inputDefaultRouter) == False:
                        flash("One of the IP addresses you introduced are not right!")
                        os.remove(inputInventory)
                        return redirect(request.url)
                    else:
                        output = dhcp_server.do_dhcp_server_config(devices_ip, devices_ostype, devices_username,
                                                                   inputPassword,
                                                                   inputEnablePassword, inputExcludeFromIP,
                                                                   inputExcludeToIP, inputPool, inputNetworkIP,
                                                                   inputNetworkMask, inputLease, inputDefaultRouter)

                        flash(output)
                        os.remove(inputInventory)
                        return redirect(request.url)

    return MyView().render('admin/forms/{0}.html'.format(template_type), template_type=template_type,
                           inventories=inventories, elements=myDict, elements2=devicesDict)


class AdminIndex(AdminIndexView):
    @expose('/')
    def index(self):
        return self.render(
            'admin/index.html')


# Create admin
admin = flask_admin.Admin(
    app,
    'My Dashboard',
    base_template='my_master.html',
    template_mode='bootstrap4',

)

# class MyHomeView(AdminIndexView):
#     @expose('/')
#     def index(self):
#         arg1 = 'Hello'
#         return self.render('admin/index.html', arg1=arg1)
#
# admin = Admin(index_view=MyHomeView())
#
# # Create admin
# admin = Admin(
#     app,
#     index_view=AdminIndexView(
#         name='Home',
#         template='admin/index.html',
#         url='/'
#     )
# )


# Add model views
# admin.add_view(MyModelView(Role, db.session, menu_icon_type='fa', menu_icon_value='fa-server', name="Roles"))
# user.add_view(UserView(User, db.session, menu_icon_type='fa', menu_icon_value='fa-users', name="Users"))
admin.add_view(UserView(User, db.session, menu_icon_type='fa', menu_icon_value='fa-users', name="Users"))
admin.add_view(
    TemplateView(name="Templates", endpoint='templates', menu_icon_type='fa', menu_icon_value='fa-connectdevelop'))
# admin.add_view(NetworkView(Network, db.session, menu_icon_type='fa', menu_icon_value='fa-desktop', name="Networks"))
admin.add_view(
    FullView(DeviceCategoryRelation, db.session, menu_icon_type='fa', menu_icon_value='fa-book', name="Full view"))
admin.add_view(DeviceView(Device, db.session, menu_icon_type='fa', menu_icon_value='fa-cube', name="Devices"))
admin.add_view(CategoryView(Category, db.session, menu_icon_type='fa', menu_icon_value='fa-cubes', name="Category"))
admin.add_view(InventoryView(Inventory, db.session, menu_icon_type='fa', menu_icon_value='fa-server', name="Inventory"))


# define a context processor for merging flask-admin's template context into the
# flask-security views.
@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
        get_url=url_for
    )


def build_sample_db():
    """
    Populate a small db with some example entries.
    """

    import string
    import random

    db.drop_all()
    db.create_all()

    with app.app_context():
        user_role = Role(name='user')
        super_user_role = Role(name='superuser')
        db.session.add(user_role)
        db.session.add(super_user_role)
        db.session.commit()

        # networks
        # network1 = Network(name='main_network', description='main network with everything')
        # network2 = Network(name='network2', description='test network')
        # db.session.add(network1)
        # db.session.add(network2)
        # db.session.commit()

        # inventories
        inventory1 = Inventory(name='inventory', user_id='1')
        db.session.add(inventory1)
        db.session.commit()

        inventory2 = Inventory(name='inventory2', user_id='2')
        db.session.add(inventory2)
        db.session.commit()

        inventory3 = Inventory(name='inventory3', user_id='1')
        db.session.add(inventory3)
        db.session.commit()

        # # categories
        # category1 = Category(name='routers', os_type='ios', username='8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', _password='e73b79a0b10f8cdb6ac7dbe4c0a5e25776e1148784b86cf98f7d6719d472af69', _enable='a80b568a237f50391d2f1f97beaf99564e33d2e1c8a2e5cac21ceda701570312', inventory_id='1')
        # db.session.add(category1)
        # db.session.commit()
        #
        # category2 = Category(name='switches', os_type='ios', username='8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', _password='e73b79a0b10f8cdb6ac7dbe4c0a5e25776e1148784b86cf98f7d6719d472af69', _enable='a80b568a237f50391d2f1f97beaf99564e33d2e1c8a2e5cac21ceda701570312', inventory_id='1')
        # db.session.add(category2)
        # db.session.commit()

        # templates
        template1 = Template(name='Running-config')
        template2 = Template(name='ACL')
        template3 = Template(name='DHCPSnooping')
        template4 = Template(name='FTP')
        template5 = Template(name='IPSG')
        template6 = Template(name='NTP')
        template7 = Template(name='OSPF')
        template8 = Template(name='SNMPv3')
        template10 = Template(name='STP')
        template11 = Template(name='Syslog')
        template12 = Template(name='TFTP')
        template13 = Template(name='ShowBackups')
        template14 = Template(name='VTYconsole')
        template15 = Template(name='Autosecure')
        template16 = Template(name='DAI')
        template17 = Template(name='DTP')
        template18 = Template(name='Banners')
        template20 = Template(name='Hostnames')
        template21 = Template(name='SecureBoot')
        template22 = Template(name='DomainName')
        template23 = Template(name='Save')
        template24 = Template(name='LoadBackup')
        template25 = Template(name='Backup')
        template26 = Template(name='Copy')
        template27 = Template(name='Users')
        template28 = Template(name='DHCPServer')
        db.session.add(template1)
        db.session.add(template2)
        db.session.add(template3)
        db.session.add(template4)
        db.session.add(template5)
        db.session.add(template6)
        db.session.add(template7)
        db.session.add(template8)
        db.session.add(template10)
        db.session.add(template11)
        db.session.add(template12)
        db.session.add(template13)
        db.session.add(template14)
        db.session.add(template15)
        db.session.add(template16)
        db.session.add(template17)
        db.session.add(template18)
        db.session.add(template20)
        db.session.add(template21)
        db.session.add(template22)
        db.session.add(template23)
        db.session.add(template24)
        db.session.add(template25)
        db.session.add(template26)
        db.session.add(template27)
        db.session.add(template28)
        db.session.commit()

        # devices
        device1 = Device(name='R1', description='router from 1st building', ip_address='192.168.122.16')
        device2 = Device(name='R2', description='router', ip_address='192.168.122.17')
        device3 = Device(name='SW1', description='switch', ip_address='192.168.122.18')
        db.session.add(device1)
        db.session.add(device2)
        db.session.add(device3)
        db.session.commit()

        # users
        test_user1 = user_datastore.create_user(
            first_name='Admin',
            email='admin',
            password=encrypt_password('admin'),
            roles=[super_user_role]
        )

        test_user2 = user_datastore.create_user(
            first_name='Anda',
            email='andamartinel@gmail.com',
            password=encrypt_password('parola'),
            roles=[super_user_role]
        )

        first_names = [
            'Harry', 'Amelia', 'Oliver', 'Jack', 'Isabella', 'Charlie', 'Sophie', 'Mia',
            'Jacob', 'Thomas', 'Emily', 'Lily', 'Ava', 'Isla', 'Alfie', 'Olivia', 'Jessica',
            'Riley', 'William', 'James', 'Geoffrey', 'Lisa', 'Benjamin', 'Stacey', 'Lucy'
        ]
        last_names = [
            'Brown', 'Smith', 'Patel', 'Jones', 'Williams', 'Johnson', 'Taylor', 'Thomas',
            'Roberts', 'Khan', 'Lewis', 'Jackson', 'Clarke', 'James', 'Phillips', 'Wilson',
            'Ali', 'Mason', 'Mitchell', 'Rose', 'Davis', 'Davies', 'Rodriguez', 'Cox', 'Alexander'
        ]

        for i in range(len(first_names)):
            tmp_email = first_names[i].lower() + "." + last_names[i].lower() + "@example.com"
            tmp_pass = ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(10))
            user_datastore.create_user(
                first_name=first_names[i],
                last_name=last_names[i],
                email=tmp_email,
                password=encrypt_password(tmp_pass),
                roles=[user_role, ]
            )
        db.session.commit()

    return


app_dir = os.path.realpath(os.path.dirname(__file__))
database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
if not os.path.exists(database_path):
    build_sample_db()
app.run(host='0.0.0.0')

if __name__ == '__main__':

    # Build a sample db on the fly, if one does not exist yet.
    app_dir = os.path.realpath(os.path.dirname(__file__))
    database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
    if not os.path.exists(database_path):
        build_sample_db()

    # Start app
    app.run(host='0.0.0.0')
