# Flask-Admin Dashboard Network Automation App

Based on https://github.com/jonalxh/Flask-Admin-Dashboard.git

Dashboard app with Admin LTE template and Flask Admin, it has:

- User Registration
- Login as general or admin user
- Roles management
- Create form in modal window by default
- Inline editing enabled by default
- Skins and  layout customization
- Templates for a number of protocols for CISCO devices
- Python automation scripts using Paramiko, Netmiko, NAPALM and Ansible
 
Utilities: 

  - AdminLTE Bootstrap template
  - Flask-Security
  - Flask-Admin
  - SQLite
  - Customized templates for protocols parameters

  ### How to use

- Clone or download the git repository.
    ```sh
    $ git clone 
    ```
- Create and activate a virtual environment:
    ```sh
    $ virtualenv venv
    $ source venv/bin/activate
    ```
- Install the requirements inside the app folder
    ```sh
    $ pip install -r requirements.txt
    ```
- Once the process finishes give execution permission to app.py file and run it
    ```sh
    $ chmod +x app.py
    $ ./app.py
    ```
- The first execution will create automatically a sample sqlite database.
- Open your favorite browser and type
    ```
    localhost:5000/admin
    ```
    then just log in with the default user or register one. 

### Screenshots
![Diagram.png](./image.png)
![FormExample.png](./image-1.png)
![FormOutput.png](./image-2.png)
![Files.png](./image-3.png)



**I hope you enjoy it.**
