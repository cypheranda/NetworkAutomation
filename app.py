#!venv/bin/python
import html
import os
import ipaddress
import re


import flask_user
from flask import Flask, url_for, redirect, render_template, request, abort, jsonify, Markup, json
from flask_admin.contrib.sqla.filters import IntGreaterFilter
from flask_admin.model import typefmt
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
from flask_security.utils import encrypt_password
import flask_admin
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers, AdminIndexView, Admin
from flask_admin import BaseView, expose
from sqlalchemy.ext.hybrid import hybrid_property
from wtforms import PasswordField
from flask_admin.form import SecureForm
from flask_admin.contrib.sqla import ModelView
from flask import Flask, render_template, request, url_for, flash, redirect

# ...
# scripts import
from templates.myscripts import netmiko_show_version, netmiko_get_devices_array, ping, paramiko_sh_ip_int_brief, netmiko_check_autosecure_config, autosecure, napalm_check_connectivity
from templates.myscripts import netmiko_get_inventory_elements, napalm_retrieve_info, napalm_ip_source_guard
from templates.myscripts import netmiko_show, netmiko_run_commands_from_file, secure_boot, dai

from os.path import join, dirname, realpath

# ...
# scripts import
from templates.myscripts import netmiko_show_version, netmiko_get_devices_array, ping, paramiko_sh_ip_int_brief

# Create Flask application
app = Flask(__name__)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)
admin_username = 'admin'
admin_password = 'cisco'
admin_enablepass = 'parola'
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


class Network(db.Model, RoleMixin):
    __tablename__ = 'network'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))
    # devices = db.relationship("Device")

    def __str__(self):
        return self.name


class Device(db.Model, RoleMixin):
    __tablename__ = 'device'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    type = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(80), nullable=False)
    os_type = db.Column(db.String(80), nullable=False)
    network_id = db.Column(db.Integer(), db.ForeignKey('network.id'), nullable=False)
    network = db.relationship("Network")

    @hybrid_property
    def ping(self):
        ip_address = self.ip_address
        return ping.do_ping(ip_address)

    @hybrid_property
    def details(self):
        # details
        hostname, uptime, version, serial, ios = netmiko_show_version.show_version(self.ip_address, self.os_type,
                                                                                   admin_username, admin_password)
        print(hostname)
        print(uptime)
        if hostname == "error":
            return "Could not connect to device!"
        data_array = []
        x = {
            "hostname": hostname,
            "uptime": uptime,
            "version": version,
            "serial": serial,
        }
        data_array.append(x)
        return json.dumps(data_array)

    @hybrid_property
    def up_interfaces(self):
        # up_interfaces
        if self.ping != "Successful ping to host!" or self.details == "Could not connect to device!":
            return "Could not connect to device!"
        interfaces, int_ipaddresses = paramiko_sh_ip_int_brief.show_ipintbrief(self.ip_address, admin_username,
                                                                               admin_password, admin_enablepass)
        data_array = []
        x = {
            "interface": interfaces,
            "ip_address": int_ipaddresses,
            }
        return data_array.append(x)


    def __str__(self):
        return self.name


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    def __str__(self):
        return self.email


class Template(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def __str__(self):
        return self.name


class Inventory(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def __str__(self):
        return self.name


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


# Create customized model view class
class MyModelView(sqla.ModelView):

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


class UserView(MyModelView):
    column_editable_list = ['email', 'first_name', 'last_name']
    column_searchable_list = column_editable_list
    column_exclude_list = ['password']
    #form_excluded_columns = column_exclude_list
    column_details_exclude_list = column_exclude_list
    column_filters = column_editable_list
    form_overrides = {
        'password': PasswordField
    }


class NetworkView(MyModelView):
    column_editable_list = ['name', 'description']
    column_searchable_list = column_editable_list
    column_filters = column_editable_list
    column_labels = {
        'name': 'Name',
        'description': 'Description',
    }


class DeviceView(MyModelView):
    column_list = ('name', 'type', 'ip_address', 'os_type', 'ping', 'details', 'up_interfaces')
    column_searchable_list = column_list
    column_filters = ['name', 'network.name']

    can_view_details = True
    details_modal = True

    column_labels = {
        'name': 'Name',
        'network.name': 'Network',
    }


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

@app.route('/admin/<template_type>', methods=['POST', 'GET'])
def find_template(template_type):
    inventories = Inventory.query.order_by(Inventory.name).all()
    myDict = {}
    for inventory in inventories:
        key = inventory.name
        inventory_id = inventory.id

        # select all devices categories for each inventory
        devices = []
        path = 'templates/myscripts/' + inventory.name
        CONFIG_PATH = os.path.join(ROOT_DIR, path)  # requires `import os`

        devices = netmiko_get_inventory_elements.get_device_data(CONFIG_PATH)

        # list
        myDict[key] = devices

    if request.method == 'POST':
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
            if not inputInventory:
                flash('Inventory is required!')
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
                path = 'templates/myscripts/' + inputInventory
                CONFIG_PATH = os.path.join(ROOT_DIR, path)  # requires `import os`
                inputSecurityBanner = 'k' + inputSecurityBanner + 'k'
                vars_array = []
                vars_array.extend([inputType, inputSecurityBanner, inputNewEnableSecret, inputNewEnablePassword, inputLocalUsername, inputLocalPassword, inputBlockingPeriod, inputLoginFailures, inputTimePeriod, inputSSHOption, inputHostname, inputDomainName, inputFirewallOption, inputTCPOption])
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(CONFIG_PATH, inputDevices)
                if ((devices_username != inputUsername) or (devices_password != inputPassword) or (devices_enable_password != inputEnablePassword)):
                    flash("These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    output = autosecure.do_autosecure(devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password, vars_array)
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
            if not inputInventory:
                flash('Inventory is required!')
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
                path = 'templates/myscripts/' + inputInventory
                CONFIG_PATH = os.path.join(ROOT_DIR, path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    CONFIG_PATH, inputDevices)
                if ((devices_username != inputUsername) or (devices_password != inputPassword) or (
                        devices_enable_password != inputEnablePassword)):
                    flash("These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                elif napalm_retrieve_info.check_interface(inputInterface, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password) == 0:
                    flash("The interface you entered is not present in all of the devices you selected!")
                else:
                    output = napalm_ip_source_guard.do_ipsg(devices_ip, devices_ostype, devices_username, devices_password,
                                                      devices_enable_password, inputType,inputIpAddress, inputMacAddress, inputVlan, inputInterface)
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
            if not inputInventory:
                flash('Inventory is required!')
            elif not inputDevices:
                flash('Devices are required!')
            else:
                path = 'templates/myscripts/' + inputInventory
                CONFIG_PATH = os.path.join(ROOT_DIR, path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    CONFIG_PATH, inputDevices)
                if ((devices_username != inputUsername) or (devices_password != inputPassword) or (
                        devices_enable_password != inputEnablePassword)):
                    flash("These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    output = secure_boot.do_secureboot(devices_ip, devices_ostype, devices_username, devices_password,
                                                      devices_enable_password, "archive_router_config")
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
            if not inputInventory:
                flash('Inventory is required!')
            elif not inputDevices:
                flash('Devices are required!')
            else:
                VLANs = split_string(inputVLANs)
                trustedInterfaces = split_string(inputTrustedInterfaces)
                untrustedInterfaces = split_string(inputUntrustedInterfaces)
                path = 'templates/myscripts/' + inputInventory
                CONFIG_PATH = os.path.join(ROOT_DIR, path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    CONFIG_PATH, inputDevices)
                if ((devices_username != inputUsername) or (devices_password != inputPassword) or (
                        devices_enable_password != inputEnablePassword)):
                    flash("These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                    for inputInterface in trustedInterfaces:
                        if napalm_retrieve_info.check_interface(inputInterface, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password) == 0:
                            flash("The trusted interface you entered is not present in all of the devices you selected!")
                    for inputInterface in untrustedInterfaces:
                        if napalm_retrieve_info.check_interface(inputInterface, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password) == 0:
                            flash("The untrusted interface you entered is not present in all of the devices you selected!")
                else:
                    output = dai.dai(devices_ip, devices_ostype, devices_username, devices_password,
                                                      devices_enable_password, VLANs, trustedInterfaces, untrustedInterfaces)
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
            if not inputInventory:
                flash('Inventory is required!')
            elif not inputDevices:
                flash('Devices are required!')
            else:
                path = 'templates/myscripts/' + inputInventory
                CONFIG_PATH = os.path.join(ROOT_DIR, path)  # requires `import os`
                devices_hostname, devices_ip, devices_ostype, devices_username, devices_password, devices_enable_password = netmiko_get_devices_array.get_device_data(
                    CONFIG_PATH, inputDevices)
                if ((devices_username != inputUsername) or (devices_password != inputPassword) or (
                        devices_enable_password != inputEnablePassword)):
                    flash("These are not the credentials from the inventory file! Please reconfigure the file accordingly.")
                else:
                    output = secure_boot.do_secureboot(devices_ip, devices_ostype, devices_username, devices_password,
                                                      devices_enable_password, "archive_router_config")
                    flash(output)
                    return redirect(request.url)

    return MyView().render('admin/forms/{0}.html'.format(template_type), template_type=template_type,
                               inventories=inventories, elements=myDict)


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


# Add model views
# admin.add_view(MyModelView(Role, db.session, menu_icon_type='fa', menu_icon_value='fa-server', name="Roles"))
admin.add_view(UserView(User, db.session, menu_icon_type='fa', menu_icon_value='fa-users', name="Users"))
admin.add_view(TemplateView(name="Templates", endpoint='templates', menu_icon_type='fa', menu_icon_value='fa-connectdevelop'))
admin.add_view(NetworkView(Network, db.session, menu_icon_type='fa', menu_icon_value='fa-desktop', name="Networks"))
admin.add_view(DeviceView(Device, db.session, menu_icon_type='fa', menu_icon_value='fa-server', name="Devices"))


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
        network1 = Network(name='main_network', description='main network with everything')
        network2 = Network(name='network2', description='test network')
        db.session.add(network1)
        db.session.add(network2)
        db.session.commit()

        # inventory files
        inventory1 = Inventory(name='inventory',)
        db.session.add(inventory1)
        db.session.commit()

        # templates
        template1 = Template(name='AAA+TACACS')
        template2 = Template(name='ACL')
        template3 = Template(name='DHCPSnooping')
        template4 = Template(name='FTP')
        template5 = Template(name='IPSG')
        template6 = Template(name='NTP')
        template7 = Template(name='OSPF')
        template8 = Template(name='SNMPv3')
        template9 = Template(name='StaticRoutes')
        template10 = Template(name='STP')
        template11 = Template(name='SYSLOG')
        template12 = Template(name='TFTP')
        template13 = Template(name='VLANs')
        template14 = Template(name='VTY+console')
        template15 = Template(name='Autosecure')
        template16 = Template(name='DAI')
        template17 = Template(name='DTP')
        template18 = Template(name='Banners')
        template19 = Template(name='PortSecurity')
        template20 = Template(name='Hostnames')
        template21 = Template(name='SecureBoot')
        db.session.add(template1)
        db.session.add(template2)
        db.session.add(template3)
        db.session.add(template4)
        db.session.add(template5)
        db.session.add(template6)
        db.session.add(template7)
        db.session.add(template8)
        db.session.add(template9)
        db.session.add(template10)
        db.session.add(template11)
        db.session.add(template12)
        db.session.add(template13)
        db.session.add(template14)
        db.session.add(template15)
        db.session.add(template16)
        db.session.add(template17)
        db.session.add(template18)
        db.session.add(template19)
        db.session.add(template20)
        db.session.add(template21)
        db.session.commit()

        # devices
        device1 = Device(name='R1', type='router', ip_address='192.168.122.16', os_type='cisco_ios', network_id='1')
        device2 = Device(name='R2', type='router', ip_address='192.168.122.17', os_type='cisco_ios', network_id='1')
        device3 = Device(name='SW1', type='switch', ip_address='192.168.122.18', os_type='cisco_ios', network_id='1')
        db.session.add(device1)
        db.session.add(device2)
        db.session.add(device3)
        db.session.commit()

        # users
        test_user1 = user_datastore.create_user(
            first_name='Admin',
            email='admin',
            password=encrypt_password('admin'),
            roles=[user_role, super_user_role]
        )

        test_user1 = user_datastore.create_user(
            first_name='Anda',
            email='andamartinel@gmail.com',
            password=encrypt_password('parola'),
            roles=[user_role]
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

if __name__ == '__main__':

    # Build a sample db on the fly, if one does not exist yet.
    app_dir = os.path.realpath(os.path.dirname(__file__))
    database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
    if not os.path.exists(database_path):
        build_sample_db()

    # Start app
    app.run(debug=True)