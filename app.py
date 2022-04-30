#!venv/bin/python
import html
import os

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
from templates.myscripts import netmiko_show_version, netmiko_get_devices_array, ping, paramiko_sh_ip_int_brief

# Create Flask application
app = Flask(__name__)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)
admin_username = 'admin'
admin_password = 'cisco'
admin_enablepass = 'parola'


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
        return ping.do_ping(self.ip_address)

    @hybrid_property
    def details(self):
        if self.ping != "Successful ping to host!":
            return "Could not connect to device!"

        # details
        hostname, uptime, version, serial, ios = netmiko_show_version.show_version(self.ip_address, self.os_type,
                                                                                   admin_username, admin_password)
        if hostname == "error":
            return "Could not connect to device!"
        data_array = []
        x = {
            "hostname": hostname,
            "uptime": uptime,
            "version": version,
            "serial": serial,
            "ios": ios
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


# templates views
class AutosecureView(ModelView):
    form_base_class = SecureForm
    form_create_rules = ('email', 'first_name', 'last_name')


# Flask views
@app.route('/')
def index():
    return render_template('index.html')


class MyView(BaseView):
    def __init__(self, *args, **kwargs):
        self._default_view = True
        super(MyView, self).__init__(*args, **kwargs)
        self.admin = admin

messages = [{'title': 'Message One',
             'content': 'Message One Content'},
            {'title': 'Message Two',
             'content': 'Message Two Content'}
            ]

@app.route('/admin/<template_type>', methods=['POST', 'GET'])
def find_template(template_type):
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        if not title:
            flash('Title is required!')
        elif not content:
            flash('Content is required!')
        else:
            messages.append({'title': title, 'content': content})
            return redirect(url_for('index'))

    inventories = Inventory.query.order_by(Inventory.name).all()
    return MyView().render('admin/forms/{0}.html'.format(template_type), template_type=template_type, inventories=inventories)


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
# admin.add_view(AutosecureModalView(name="Autosecure", endpoint='autosecure', menu_icon_type='fa', menu_icon_value='fa-connectdevelop'))
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
        inventory2 = Inventory(name='devices.txt')
        db.session.add(inventory1)
        db.session.add(inventory2)
        db.session.commit()

        # templates
        template1 = Template(name='AAA+TACACS')
        template2 = Template(name='ACL')
        template3 = Template(name='DHCP snooping')
        template4 = Template(name='FTP')
        template5 = Template(name='IPSG')
        template6 = Template(name='NTP')
        template7 = Template(name='OSPF')
        template8 = Template(name='SNMPv3')
        template9 = Template(name='Static routes')
        template10 = Template(name='STP')
        template11 = Template(name='SYSLOG')
        template12 = Template(name='TFTP')
        template13 = Template(name='VLANs')
        template14 = Template(name='VTY+console')
        template15 = Template(name='Autosecure')
        template16 = Template(name='DAI')
        template17 = Template(name='DTP')
        template18 = Template(name='Banners')
        template19 = Template(name='Port security')
        template20 = Template(name='Hostnames')
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

if __name__ == '__main__':

    # Build a sample db on the fly, if one does not exist yet.
    app_dir = os.path.realpath(os.path.dirname(__file__))
    database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
    if not os.path.exists(database_path):
        build_sample_db()

    # Start app
    app.run(debug=True)