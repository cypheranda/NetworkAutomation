# util pt snmpv3 si acl
import os
import shutil
from pathlib import Path

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

def crete_dir(path, type):
    # Check whether the specified path exists or not
    isExist = os.path.exists(path)

    if not isExist:
        # Create a new directory because it does not exist
        os.makedirs(path)
        print("The new directory is created!")

    fle = Path(path+'/'+type+".yaml")
    fle.touch(exist_ok=True)

def copy_from_device_to_devices(from_hostname, to_hostnames, type):
    src_path = 'host_vars/' + from_hostname + "/" + type + ".yaml"
    source = os.path.join(ROOT_DIR, src_path)  # requires `import os`

    if os.path.exists(source):
        for hostname in to_hostnames:
            crete_dir(os.path.join(ROOT_DIR, 'host_vars/' + hostname), type)
            dest_path = 'host_vars/' + hostname + "/" + type + ".yaml"
            destination = os.path.join(ROOT_DIR, dest_path)  # requires `import os`
            if destination == source:
                return "The source file and destination files are the same!"
            else:
                shutil.copy(source, destination)
    else:
        return "Error! The source file does not exist! Create it first"

    return "Success"

# copy_from_device_to_devices('R20', ['R1','R2'], 'snmpv3')