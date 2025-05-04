#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: Sandeep Wawdane
# Copyright (c) 2025

from __future__ import print_function

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*TripleDES.*")

"""
MobApp-Data-Extractor : Tool for extracting APKs/IPAs and app data from rooted Android and jailbroken iOS devices.

A unified tool for extracting and analyzing mobile applications on both Android and iOS platforms.
Supports APK extraction, IPA dumping, and local storage extraction.

Usage:
  Android:
    python3 MobApp-Data-Extractor.py android list-all
    python3 MobApp-Data-Extractor.py android list-user
    python3 MobApp-Data-Extractor.py android get-apk <package_name>
    python3 MobApp-Data-Extractor.py android get-data <package_name>
  
  iOS:
    python3 MobApp-Data-Extractor.py ios list-all
    python3 MobApp-Data-Extractor.py ios get-ipa <package_name>
    python3 MobApp-Data-Extractor.py ios get-data <package_name>

Options:
  -o, --output        Specify name of the output file (for get-ipa)
  -H, --host          Specify SSH hostname (default: localhost)
  -p, --port          Specify SSH port (default: 2222)
  -u, --user          Specify SSH username (default: root)
  -P, --password      Specify SSH password (default: alpine)
  -K, --key           Specify SSH private key file path
  -h, --help          Show this help message
"""
import sys
import os
import shutil
import time
import argparse
import tempfile
import subprocess
import re
import json
import zipfile
import socket
import tarfile
import traceback
import threading
from pathlib import Path

# Check if required packages are installed
try:
    import frida
    import paramiko
    from paramiko import SSHClient
    from scp import SCPClient
    from tqdm import tqdm
except ImportError:
    print("Required packages not found. Installing paramiko, frida, scp, and tqdm...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko", "frida", "frida-tools", "scp", "tqdm"])
    import frida
    import paramiko
    from paramiko import SSHClient
    from scp import SCPClient
    from tqdm import tqdm

# Python 2/3 compatibility
IS_PY2 = sys.version_info[0] < 3
if IS_PY2:
    reload(sys)
    sys.setdefaultencoding('utf8')

# Script directory and paths
script_dir = os.path.dirname(os.path.realpath(__file__))
APP_DUMPER_JS = os.path.join(script_dir, 'app-dumper.js')
STORAGE_LOCATOR_JS = os.path.join(script_dir, 'storage-locator.js')

# Default SSH settings for iOS
IOS_SSH_USER = 'root'
IOS_SSH_PASSWORD = 'alpine'
IOS_SSH_HOST = 'localhost'
IOS_SSH_PORT = 2222
IOS_SSH_KEY_FILE = None

# Temp directories
TEMP_DIR = tempfile.gettempdir()
PAYLOAD_DIR = 'Payload'
PAYLOAD_PATH = os.path.join(TEMP_DIR, PAYLOAD_DIR)
STORAGE_PATH = os.path.join(TEMP_DIR, 'AppStorage')

# Global variables
file_dict = {}
finished = threading.Event()

# Output directories
OUTPUT_BASE = os.path.join(os.getcwd(), 'output')
OUTPUT_IOS_IPA_DIR = os.path.join(OUTPUT_BASE, 'ios', 'ipas')
OUTPUT_IOS_DATA_DIR = os.path.join(OUTPUT_BASE, 'ios', 'data')
OUTPUT_ANDROID_APK_DIR = os.path.join(OUTPUT_BASE, 'android', 'apks')
OUTPUT_ANDROID_DATA_DIR = os.path.join(OUTPUT_BASE, 'android', 'data')



def create_output_structure():
    """Create the output directory structure if it doesn't exist."""
    os.makedirs(OUTPUT_IOS_IPA_DIR, exist_ok=True)
    os.makedirs(OUTPUT_IOS_DATA_DIR, exist_ok=True)
    os.makedirs(OUTPUT_ANDROID_APK_DIR, exist_ok=True)
    os.makedirs(OUTPUT_ANDROID_DATA_DIR, exist_ok=True)
    print("Created output directory structure.")

def create_dir(path):
    """Create a directory, removing it first if it exists"""
    path = path.strip()
    path = path.rstrip('\\')
    if os.path.exists(path):
        shutil.rmtree(path)
    try:
        os.makedirs(path)
    except os.error as err:
        print(err)



def run_adb(args, capture=True):
    """Run an ADB command"""
    cmd = ["adb"] + args
    if capture:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            print(f"Error: adb {' '.join(args)} failed (exit {res.returncode})")
            print(f"Error message: {res.stderr}")
            return None
        return res.stdout
    else:
        res = subprocess.run(cmd)
        if res.returncode != 0:
            print(f"Error: adb {' '.join(args)} failed (exit {res.returncode})")
            return False
        return True

def check_adb():
    """Check if ADB is available"""
    try:
        subprocess.run(["adb", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        print("Error: ADB not found. Please install Android SDK Platform Tools.")
        return False

def list_android_packages(user_only=False):
    """List Android packages"""
    if not check_adb():
        return False
    
    flag = ["-3"] if user_only else []
    out = run_adb(["shell", "pm", "list", "packages"] + flag)
    
    if out is None:
        return False
    
    names = [ln.replace("package:", "").strip() for ln in out.splitlines() if ln.startswith("package:")]
    
    print("\nInstalled Android packages:")
    print("=" * 50)
    for nm in names:
        print(nm)
    print("-" * 50)
    print(f"Total: {len(names)} packages")
    
    return True

def get_android_apk(package_name):
    """Extract APK file(s) for the given package name"""
    if not check_adb():
        return False
    
    # Get paths to all APK files for the package
    out = run_adb(["shell", "pm", "path", package_name])
    
    if out is None:
        print(f"Error: Package '{package_name}' not found.")
        return False
    
    paths = [ln.replace("package:", "").strip() for ln in out.splitlines() if ln.startswith("package:")]
    
    if not paths:
        print(f"Error: No APK found for '{package_name}'. Check package name?")
        return False
    
    # Create output directory
    output_dir = os.path.join(OUTPUT_ANDROID_APK_DIR, package_name)
    os.makedirs(output_dir, exist_ok=True)
    
    # Pull each APK file
    success = True
    for apk_path in paths:
        apk_name = os.path.basename(apk_path)
        output_path = os.path.join(output_dir, apk_name)
        
        print(f"Pulling {apk_path} to {output_path}...")
        if not run_adb(["pull", apk_path, output_path], capture=False):
            success = False
        else:
            print(f"Successfully extracted: {output_path}")
    
    if success:
        print(f"\nAll APK files for '{package_name}' extracted to: {output_dir}")
    
    return success

def get_android_data(package_name):
    """Extract app data for the given package name (requires root)"""
    if not check_adb():
        return False
    
    # Check if device is rooted
    root_check = run_adb(["shell", "su", "-c", "id"])
    if root_check is None or "uid=0" not in root_check:
        print("Error: Device is not rooted or su binary is not available.")
        print("Root access is required to extract app data.")
        return False
    
    # Check if package exists
    package_check = run_adb(["shell", "pm", "path", package_name])
    if package_check is None or not package_check.strip():
        print(f"Error: Package '{package_name}' not found.")
        return False
    
    # Create temporary archive on device
    print(f"Creating data archive for '{package_name}' on device...")
    sd_tar = f"/sdcard/{package_name}.tar.gz"
    
    # Remove any existing archive
    run_adb(["shell", "rm", "-f", sd_tar])
    
    # Create new archive
    cmd = f"su -c 'cd /data/data/{package_name} && tar czf {sd_tar} .'"
    if not run_adb(["shell", cmd], capture=False):
        print("Error: Failed to create data archive on device.")
        return False
    
    # Create output directory
    output_dir = os.path.join(OUTPUT_ANDROID_DATA_DIR, package_name)
    os.makedirs(output_dir, exist_ok=True)
    
    # Pull the archive
    local_tar = os.path.join(output_dir, f"{package_name}.tar.gz")
    print(f"Pulling data archive to {local_tar}...")
    if not run_adb(["pull", sd_tar, local_tar], capture=False):
        print("Error: Failed to pull data archive from device.")
        return False
    
    # Remove the archive from device
    run_adb(["shell", f"rm -f {sd_tar}"])
    
    # Extract the archive
    print(f"Extracting data to {output_dir}...")
    try:
        with tarfile.open(local_tar, mode='r:gz') as tar:
            tar.extractall(path=output_dir)
        
        # Remove the local archive
        os.remove(local_tar)
        
        print(f"Successfully extracted app data to: {output_dir}")
        return True
    except Exception as e:
        print(f"Error extracting archive: {e}")
        return False



def start_iproxy():
    """Start iproxy on port 2222 if it's not already running."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(('localhost', 2222)) != 0:
            print("Starting iproxy...")
            subprocess.Popen(['iproxy', '2222', '22'])
            time.sleep(2)

def restart_iproxy():
    """Restart iproxy by killing existing processes and starting a new one."""
    # Kill existing iproxy processes
    try:
        pids = subprocess.check_output(['pgrep', 'iproxy']).decode().strip().split('\n')
        for pid in pids:
            if pid:
                subprocess.run(['kill', '-9', pid])
    except subprocess.CalledProcessError:
        pass  # No iproxy processes found

    # Kill processes using port 2222
    try:
        pids = subprocess.check_output(['lsof', '-ti:2222']).decode().strip().split('\n')
        for pid in pids:
            if pid:
                subprocess.run(['kill', '-9', pid])
    except subprocess.CalledProcessError:
        pass  # No processes using port 2222

    # Start new iproxy
    subprocess.Popen(['iproxy', '2222', '22'])
    time.sleep(2)

    # Test SSH connection
    try:
        subprocess.check_call(['nc', '-z', 'localhost', '2222'])
        print("SSH connection is available on port 2222.")
    except subprocess.CalledProcessError:
        print("SSH connection test failed. Please check your device connection.")

def check_frida():
    """Check if Frida is available"""
    try:
        import frida
        return True
    except ImportError:
        print("Error: Frida not found. Please install Frida: pip install frida frida-tools")
        return False

def get_ios_device():
    """Get the first available iOS device with priority for USB devices"""
    try:
        device_manager = frida.get_device_manager()
        devices = device_manager.enumerate_devices()
        
        # First try to get a USB device
        for device in devices:
            if device.type == 'usb':
                return device
        
        # If no USB device, try to get a local device
        for device in devices:
            if device.type == 'local':
                return device
        
        # If no local device, try to get a remote device
        for device in devices:
            if device.type == 'remote':
                return device
        
        print("Error: No iOS device found.")
        return None
    except Exception as e:
        print(f"Error getting device: {e}")
        return None

def get_usb_iphone():
    """Get USB connected iPhone with event waiting"""
    Type = 'usb'
    if int(frida.__version__.split('.')[0]) < 12:
        Type = 'tether'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)

    device = None
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == Type]
        if len(devices) == 0:
            print('Waiting for USB device...')
            changed.wait()
        else:
            device = devices[0]

    device_manager.off('changed', on_changed)

    return device



def list_ios_applications():
    """List all iOS applications using frida-ps"""
    if not check_frida():
        return False
    
    try:
        print("\nListing all iOS applications:")
        print("=" * 50)
        subprocess.run(['frida-ps', '-Uai'])
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error listing iOS apps: {e}")
        return False
    except FileNotFoundError:
        print("Error: frida-ps command not found. Make sure Frida is installed correctly.")
        return False

def get_applications(device):
    """Get all applications from the device"""
    try:
        applications = device.enumerate_applications()
        return applications
    except Exception as e:
        print(f'Failed to enumerate applications: {e}')
        return []

def compare_applications(a, b):
    """Compare applications for sorting"""
    a_is_running = a.pid != 0
    b_is_running = b.pid != 0
    if a_is_running == b_is_running:
        if a.name > b.name:
            return 1
        elif a.name < b.name:
            return -1
        else:
            return 0
    elif a_is_running:
        return -1
    else:
        return 1

def cmp_to_key(mycmp):
    """Convert a cmp= function into a key= function"""
    class K:
        def __init__(self, obj):
            self.obj = obj

        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0

        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0

        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0

        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0

        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0

        def __ne__(self, other):
            return mycmp(self.obj, other.obj) != 0

    return K

def open_target_app(device, name_or_bundleid):
    """Open the target app and return session, display_name, and bundle_identifier"""
    print(f'Starting the target app: {name_or_bundleid}')

    pid = ''
    session = None
    display_name = ''
    bundle_identifier = ''
    for application in get_applications(device):
        if name_or_bundleid == application.identifier or name_or_bundleid == application.name:
            pid = application.pid
            display_name = application.name
            bundle_identifier = application.identifier

    try:
        if not pid:
            pid = device.spawn([bundle_identifier])
            session = device.attach(pid)
            device.resume(pid)
        else:
            session = device.attach(pid)
    except Exception as e:
        print(f"Error attaching to process: {e}") 

    return session, display_name, bundle_identifier

#
# iOS IPA Extraction Functions
#

def load_js_file(session, filename):
    """Load a JavaScript file into a Frida session"""
    import threading
    global finished
    finished = threading.Event()
    
    source = ''
    with open(filename, 'r', encoding='utf-8') as f:
        source = source + f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()

    return script

def on_message(message, data):
    """Handle messages from Frida scripts"""
    t = tqdm(unit='B', unit_scale=True, unit_divisor=1024, miniters=1)
    last_sent = [0]

    def progress(filename, size, sent):
        baseName = os.path.basename(filename)
        if IS_PY2 or isinstance(baseName, bytes):
            t.desc = baseName.decode("utf-8")
        else:
            t.desc = baseName
        t.total = size
        t.update(sent - last_sent[0])
        last_sent[0] = 0 if size == sent else sent

    if 'payload' in message:
        payload = message['payload']
        if 'dump' in payload:
            origin_path = payload['path']
            dump_path = payload['dump']

            scp_from = dump_path
            scp_to = PAYLOAD_PATH + '/'

            with SCPClient(ssh.get_transport(), progress=progress, socket_timeout=60) as scp:
                scp.get(scp_from, scp_to)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(dump_path))
            chmod_args = ('chmod', '655', chmod_dir)
            try:
                subprocess.check_call(chmod_args)
            except subprocess.CalledProcessError as err:
                print(err)

            index = origin_path.find('.app/')
            file_dict[os.path.basename(dump_path)] = origin_path[index + 5:]

        if 'app' in payload:
            app_path = payload['app']

            scp_from = app_path
            scp_to = PAYLOAD_PATH + '/'
            with SCPClient(ssh.get_transport(), progress=progress, socket_timeout=60) as scp:
                scp.get(scp_from, scp_to, recursive=True)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(app_path))
            chmod_args = ('chmod', '755', chmod_dir)
            try:
                subprocess.check_call(chmod_args)
            except subprocess.CalledProcessError as err:
                print(err)

            file_dict['app'] = os.path.basename(app_path)

        if 'done' in payload:
            finished.set()
    t.close()

def generate_ipa(path, display_name, bundle_id=None):
    """Generate an IPA file from the extracted app"""
    # Create app-specific directory in the output structure
    app_dir_name = bundle_id or display_name
    output_dir = os.path.join(OUTPUT_IOS_IPA_DIR, app_dir_name)
    os.makedirs(output_dir, exist_ok=True)
    
    ipa_filename = display_name + '.ipa'
    ipa_path = os.path.join(output_dir, ipa_filename)

    print(f'Generating "{ipa_path}"')
    try:
        app_name = file_dict['app']

        for key, value in file_dict.items():
            from_dir = os.path.join(path, key)
            to_dir = os.path.join(path, app_name, value)
            if key != 'app':
                shutil.move(from_dir, to_dir)

        target_dir = './' + PAYLOAD_DIR
        zip_args = ('zip', '-qr', ipa_path, target_dir)
        subprocess.check_call(zip_args, cwd=TEMP_DIR)
        shutil.rmtree(PAYLOAD_PATH)
        print(f"IPA file saved to: {ipa_path}")
        return True
    except Exception as e:
        print(f"Error generating IPA: {e}")
        finished.set()
        return False

def start_dump(session, ipa_name, bundle_id=None):
    """Start the dumping process"""
    print(f'Dumping {ipa_name} to {TEMP_DIR}')

    script = load_js_file(session, APP_DUMPER_JS)
    script.post('dump')
    finished.wait()

    result = generate_ipa(PAYLOAD_PATH, ipa_name, bundle_id)

    if session:
        session.detach()
    
    return result

def get_ios_ipa(name_or_bundleid, output_ipa=None):
    """Main function to dump an app to an IPA file"""
    global ssh
    
    if not check_frida():
        return False
    
    # Start iproxy if needed
    start_iproxy()
    
    try:
        # Connect to device via SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(IOS_SSH_HOST, port=IOS_SSH_PORT, username=IOS_SSH_USER, 
                   password=IOS_SSH_PASSWORD, key_filename=IOS_SSH_KEY_FILE)

        # Create payload directory
        create_dir(PAYLOAD_PATH)
        
        # Get device and open app
        device = get_usb_iphone()
        (session, display_name, bundle_identifier) = open_target_app(device, name_or_bundleid)
        
        if not session:
            print(f"Error: Could not attach to app '{name_or_bundleid}'")
            return False
        
        if output_ipa is None:
            output_ipa = display_name
        output_ipa = re.sub(r'\.ipa$', '', output_ipa)
        
        # Start dumping process
        result = start_dump(session, output_ipa, bundle_identifier)
        return result
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        print(f"SSH connection error: {e}")
        print('Try specifying -H/--host and/or -p/--port')
        return False
    except paramiko.AuthenticationException as e:
        print(f"SSH authentication error: {e}")
        print('Try specifying -u/--user and/or -P/--password')
        return False
    except Exception as e:
        print(f'Error: {e}')
        traceback.print_exc()
        return False
    finally:
        if 'ssh' in locals() and ssh:
            ssh.close()
        if os.path.exists(PAYLOAD_PATH):
            shutil.rmtree(PAYLOAD_PATH)

#
# iOS Storage Extraction Functions
#

def get_app_info(device, bundle_id):
    """Get app info using frida"""
    try:
        # First try to attach to the running app
        try:
            print(f"Trying to attach to running app: {bundle_id}")
            session = device.attach(bundle_id)
        except frida.ProcessNotFoundError:
            # If app is not running, try to spawn it
            print(f"App not running. Spawning app: {bundle_id}")
            pid = device.spawn([bundle_id])
            session = device.attach(pid)
            device.resume(pid)
            # Give the app a moment to start
            time.sleep(2)
        
        # Load the storage locator script
        with open(STORAGE_LOCATOR_JS, 'r') as f:
            script_content = f.read()
        
        # Create and load the script
        script = session.create_script(script_content)
        script.load()
        
        print("Getting app info...")
        app_info = script.exports.getappinfo()
        
        session.detach()
        return app_info
    except Exception as e:
        print(f"Error getting app info: {e}")
        return None

def get_container_path_via_ssh(bundle_id):
    """Get container path using SSH and find command"""
    try:
        print(f"Trying to find container path via SSH for bundle ID: {bundle_id}")
        
        # Connect to device
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(IOS_SSH_HOST, port=IOS_SSH_PORT, username=IOS_SSH_USER, 
                       password=IOS_SSH_PASSWORD, key_filename=IOS_SSH_KEY_FILE, 
                       timeout=10, banner_timeout=10)
            
            # Use find command to locate the app's container
            cmd = f"find /var/mobile/Containers/Data/Application -name '.com.apple.mobile_container_manager.metadata.plist' -exec grep -l '{bundle_id}' {{}} \\;"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            
            # Read the output
            metadata_files = stdout.read().decode().strip().split('\n')
            
            if metadata_files and metadata_files[0]:
                # Get the container path from the metadata file path
                for metadata_file in metadata_files:
                    if metadata_file:
                        container_path = os.path.dirname(metadata_file)
                        print(f"Found container path: {container_path}")
                        
                        # Verify this is the correct container by checking for Documents directory
                        stdin, stdout, stderr = ssh.exec_command(f"ls -la {container_path}/Documents")
                        if stdout.channel.recv_exit_status() == 0:
                            # Try to get the app name from Info.plist
                            try:
                                # First get the bundle path
                                cmd = f"cat {metadata_file} | grep -A1 'MCMMetadataURLString' | grep 'string' | sed 's/.*<string>\\(.*\\)<\\/string>.*/\\1/'"
                                stdin, stdout, stderr = ssh.exec_command(cmd)
                                bundle_path = stdout.read().decode().strip()
                                
                                if bundle_path:
                                    # Extract the app name from Info.plist
                                    cmd = f"cat {bundle_path}/Info.plist | grep -A1 'CFBundleDisplayName' | grep 'string' | sed 's/.*<string>\\(.*\\)<\\/string>.*/\\1/'"
                                    stdin, stdout, stderr = ssh.exec_command(cmd)
                                    app_name = stdout.read().decode().strip()
                                    
                                    if app_name:
                                        print(f"Found app name: {app_name}")
                                        return container_path, app_name
                            except Exception as e:
                                print(f"Error getting app name: {e}")
                            
                            return container_path, None
            
            print("Container path not found via SSH")
            return None, None
            
        except Exception as e:
            print(f"SSH error: {e}")
            return None, None
        finally:
            ssh.close()
            
    except Exception as e:
        print(f"Error finding container path via SSH: {e}")
        return None, None

def progress_callback(filename, size, sent):
    """Progress callback for SCP transfers"""
    sys.stdout.write(f"\r{filename}: {sent}/{size} bytes transferred")
    sys.stdout.flush()

def extract_storage(container_path, app_name, bundle_id=None, device=None, app_info=None):
    """Extract storage from a specific container path"""
    print(f"Extracting storage from: {container_path}")
    
    # Extract UUID from container path
    uuid = "unknown"
    path_parts = container_path.split('/')
    for part in path_parts:
        # Check if part matches UUID pattern (8-4-4-4-12 hex digits)
        if len(part) == 36 and part.count('-') == 4:
            uuid = part
            break
    
    # Create temp directory
    if os.path.exists(STORAGE_PATH):
        shutil.rmtree(STORAGE_PATH)
    os.makedirs(STORAGE_PATH)
    
    # Create the UUID directory to preserve the path structure
    uuid_dir = os.path.join(STORAGE_PATH, uuid)
    os.makedirs(uuid_dir, exist_ok=True)
    
    # Connect to device
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        print(f"Connecting to {IOS_SSH_HOST}:{IOS_SSH_PORT} as {IOS_SSH_USER}...")
        ssh.connect(IOS_SSH_HOST, port=IOS_SSH_PORT, username=IOS_SSH_USER, 
                   password=IOS_SSH_PASSWORD, key_filename=IOS_SSH_KEY_FILE, 
                   timeout=10, banner_timeout=10)
        
        # Create directories for Documents and Library under the UUID directory
        docs_dir = os.path.join(uuid_dir, 'Documents')
        lib_dir = os.path.join(uuid_dir, 'Library')
        os.makedirs(docs_dir, exist_ok=True)
        os.makedirs(lib_dir, exist_ok=True)
        
        # Download Documents
        docs_path = os.path.join(container_path, 'Documents')
        print(f"Downloading Documents from: {docs_path}")
        try:
            with SCPClient(ssh.get_transport(), progress=progress_callback, socket_timeout=120) as scp:
                # First check if the directory exists
                stdin, stdout, stderr = ssh.exec_command(f"ls -la {docs_path}")
                if stdout.channel.recv_exit_status() == 0:
                    # Download directly to the UUID/Documents directory
                    scp.get(docs_path, uuid_dir, recursive=True)
                    print("\nDocuments downloaded successfully")
                else:
                    print(f"\nWarning: Documents directory not found at {docs_path}")
        except Exception as e:
            print(f"\nError downloading Documents: {e}")
        
        # Download Library
        lib_path = os.path.join(container_path, 'Library')
        print(f"Downloading Library from: {lib_path}")
        try:
            with SCPClient(ssh.get_transport(), progress=progress_callback, socket_timeout=120) as scp:
                # First check if the directory exists
                stdin, stdout, stderr = ssh.exec_command(f"ls -la {lib_path}")
                if stdout.channel.recv_exit_status() == 0:
                    # Download directly to the UUID/Library directory
                    scp.get(lib_path, uuid_dir, recursive=True)
                    print("\nLibrary downloaded successfully")
                else:
                    print(f"\nWarning: Library directory not found at {lib_path}")
        except Exception as e:
            print(f"\nError downloading Library: {e}")
        
        # Create output directory for this app
        app_dir_name = bundle_id or (app_info.get('bundleId') if app_info else app_name)
        output_dir = os.path.join(OUTPUT_IOS_DATA_DIR, app_dir_name)
        os.makedirs(output_dir, exist_ok=True)
        
        # Create a metadata file with all the important information
        metadata_path = os.path.join(STORAGE_PATH, 'extraction_metadata.json')
        metadata = {
            'app_name': app_name,
            'bundle_id': bundle_id or (app_info.get('bundleId') if app_info else 'Unknown'),
            'container_path': container_path,
            'uuid': uuid,
            'extraction_timestamp': time.time(),
            'device_info': {
                'name': device.name if device else 'Unknown',
                'id': device.id if device else 'Unknown',
                'type': device.type if device else 'Unknown'
            }
        }
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=4)
        
        # Copy all files directly to the output directory
        print(f"Copying files to: {output_dir}")
        
        # Copy metadata file
        shutil.copy(metadata_path, os.path.join(output_dir, os.path.basename(metadata_path)))
        
        # Copy all other files, preserving the structure
        for root, dirs, files in os.walk(STORAGE_PATH):
            for file in files:
                file_path = os.path.join(root, file)
                # Skip the metadata file as we've already copied it
                if file_path == metadata_path:
                    continue
                
                # Get the relative path and create the destination directory
                rel_path = os.path.relpath(root, STORAGE_PATH)
                dest_dir = os.path.join(output_dir, rel_path)
                os.makedirs(dest_dir, exist_ok=True)
                
                # Copy the file
                shutil.copy2(file_path, os.path.join(dest_dir, file))
        
        print(f"Local storage extracted to: {output_dir}")
        
        # Clean up
        shutil.rmtree(STORAGE_PATH)
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        # Make sure to clean up even if there's an error
        if os.path.exists(STORAGE_PATH):
            shutil.rmtree(STORAGE_PATH)
        return False
    finally:
        ssh.close()

def get_ios_data(bundle_id):
    """Main function to extract app storage"""
    if not check_frida():
        return False
    
    # Start iproxy if needed
    start_iproxy()
    
    # Try to get container path using Frida first
    container_path = None
    app_name = bundle_id.split('.')[-1]
    
    try:
        # Get the device
        device = get_ios_device()
        if device:
            # Get app info
            app_info = get_app_info(device, bundle_id)
            if app_info:
                # Print app info
                print("\nApp Info:")
                print(f"Bundle ID: {app_info.get('bundleId', 'Unknown')}")
                print(f"Display Name: {app_info.get('displayName', 'Unknown')}")
                print(f"Data Container Path: {app_info.get('dataContainerPath', 'Unknown')}")
                print(f"Bundle Path: {app_info.get('bundlePath', 'Unknown')}")
                
                # Get container path
                container_path = app_info.get('dataContainerPath')
                
                # Get app name
                if app_info.get('displayName'):
                    app_name = app_info.get('displayName')
    except Exception as e:
        print(f"Error using Frida: {e}")
    
    # If Frida failed, try SSH method
    if not container_path:
        print("Frida method failed. Trying SSH method...")
        container_path, ssh_app_name = get_container_path_via_ssh(bundle_id)
        if ssh_app_name:
            app_name = ssh_app_name
    
    # Extract storage if we found a container path
    if container_path:
        # If we still don't have a good app name, use a better default
        if app_name == "Unknown" or not app_name:
            # Try to get a better name from the bundle ID
            parts = bundle_id.split('.')
            if len(parts) > 2:
                app_name = parts[-1].capitalize()
            else:
                app_name = bundle_id.split('.')[-1]
        
        print(f"Using app name: {app_name}")
        return extract_storage(container_path, app_name, bundle_id=bundle_id, device=device, app_info=app_info)
    else:
        print("Failed to get data container path. Cannot extract local storage.")
        return False

def display_banner():
    """Display a modern, minimal CLI banner - Author: Sandeep Wawdane"""
    from tqdm import tqdm
    import time
    import random
    
    print("\033c", end="")
    
    CYAN = "\033[36m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    print(f"\n{BOLD}{CYAN}╭─────────────────────────────╮{RESET}")
    print(f"{BOLD}{CYAN}│{RESET}                             {BOLD}{CYAN}│{RESET}")
    print(f"{BOLD}{CYAN}│{RESET}  {BOLD}{MAGENTA}MobApp Data Extractor{RESET} {GREEN}v2.0{RESET} {BOLD}{CYAN}│{RESET}")
    print(f"{BOLD}{CYAN}│{RESET}                             {BOLD}{CYAN}│{RESET}")
    print(f"{BOLD}{CYAN}╰─────────────────────────────╯{RESET}\n")
    
    print(f"{YELLOW}Initializing components...{RESET}")
    
    spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    steps = 20
    
    for i in range(steps):
        progress = int((i + 1) / steps * 100)
        bar_length = 20
        completed = int(bar_length * progress / 100)
        
        bar = ""
        for j in range(bar_length):
            if j < completed:
                if j < bar_length * 0.3:
                    bar += f"{MAGENTA}■{RESET}"
                elif j < bar_length * 0.6:
                    bar += f"{BLUE}■{RESET}"
                else:
                    bar += f"{CYAN}■{RESET}"
            else:
                bar += "□"
        
        spinner = spinners[i % len(spinners)]
        sys.stdout.write(f"\r{CYAN}{spinner}{RESET} {bar} {BOLD}{progress}%{RESET}")
        sys.stdout.flush()
        time.sleep(random.uniform(0.05, 0.15))
    
    sys.stdout.write(f"\r{GREEN}✓{RESET} {CYAN}■■■■■■■■■■■■■■■■■■■■{RESET} {BOLD}100%{RESET}     \n\n")
    
    print(f"{BOLD}{BLUE}Usage:{RESET}")
    print(f"  {BOLD}{MAGENTA}Android:{RESET}")
    print(f"    {GREEN}python3 MobApp-Data-Extractor.py android list-all{RESET}")
    print(f"    {GREEN}python3 MobApp-Data-Extractor.py android list-user{RESET}")
    print(f"    {GREEN}python3 MobApp-Data-Extractor.py android get-apk{RESET} {YELLOW}<package_name>{RESET}")
    print(f"    {GREEN}python3 MobApp-Data-Extractor.py android get-data{RESET} {YELLOW}<package_name>{RESET}")
    print()
    print(f"  {BOLD}{MAGENTA}iOS:{RESET}")
    print(f"    {GREEN}python3 MobApp-Data-Extractor.py ios list-all{RESET}")
    print(f"    {GREEN}python3 MobApp-Data-Extractor.py ios get-ipa{RESET} {YELLOW}<package_name>{RESET}")
    print(f"    {GREEN}python3 MobApp-Data-Extractor.py ios get-data{RESET} {YELLOW}<package_name>{RESET}")
    print(f"\n{CYAN}{'─' * 30}{RESET}\n")

def main():

    if len(sys.argv) <= 1 or (len(sys.argv) == 2 and sys.argv[1] in ['-h', '--help']):
        display_banner()
    
    parser = argparse.ArgumentParser(
        description='MobApp-Data-Extractor - Cross-platform mobile app analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Android:
    python3 MobApp-Data-Extractor.py android list-all
    python3 MobApp-Data-Extractor.py android list-user
    python3 MobApp-Data-Extractor.py android get-apk com.example.app
    python3 MobApp-Data-Extractor.py android get-data com.example.app
  
  iOS:
    python3 MobApp-Data-Extractor.py ios list-all
    python3 MobApp-Data-Extractor.py ios get-ipa com.example.app
    python3 MobApp-Data-Extractor.py ios get-data com.example.app
        """
    )
    
    # Add platform subparsers
    platform_subparsers = parser.add_subparsers(dest='platform', required=True, help='Mobile platform')
    
    # Android subparser
    android_parser = platform_subparsers.add_parser('android', help='Android commands')
    android_subparsers = android_parser.add_subparsers(dest='command', required=True, help='Android command')
    
    # Android list-all command
    android_subparsers.add_parser('list-all', help='List all installed packages (system + user)')
    
    # Android list-user command
    android_subparsers.add_parser('list-user', help='List only user-installed packages')
    
    # Android get-apk command
    android_get_apk = android_subparsers.add_parser('get-apk', help='Pull APK file(s) for the given package name')
    android_get_apk.add_argument('package_name', help='Android package name')
    
    # Android get-data command
    android_get_data = android_subparsers.add_parser('get-data', help='Pull app local storage (requires root)')
    android_get_data.add_argument('package_name', help='Android package name')
    
    # iOS subparser
    ios_parser = platform_subparsers.add_parser('ios', help='iOS commands')
    ios_subparsers = ios_parser.add_subparsers(dest='command', required=True, help='iOS command')
    
    # iOS list-all command
    ios_subparsers.add_parser('list-all', help='List all installed apps')
    
    # iOS get-ipa command
    ios_get_ipa = ios_subparsers.add_parser('get-ipa', help='Dump a decrypted IPA')
    ios_get_ipa.add_argument('package_name', help='iOS bundle identifier or app name')
    ios_get_ipa.add_argument('-o', '--output', dest='output_name', help='Specify name of the decrypted IPA')
    
    # iOS get-data command
    ios_get_data = ios_subparsers.add_parser('get-data', help='Extract app Documents & Library storage')
    ios_get_data.add_argument('package_name', help='iOS bundle identifier')
    
    # Common SSH options for iOS commands
    for p in [ios_get_ipa, ios_get_data]:
        p.add_argument('-H', '--host', dest='ssh_host', help='Specify SSH hostname')
        p.add_argument('-p', '--port', type=int, dest='ssh_port', help='Specify SSH port')
        p.add_argument('-u', '--user', dest='ssh_user', help='Specify SSH username')
        p.add_argument('-P', '--password', dest='ssh_password', help='Specify SSH password')
        p.add_argument('-K', '--key', dest='ssh_key_filename', help='Specify SSH private key file path')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create output structure
    create_output_structure()
    
    # Update SSH settings if provided
    global IOS_SSH_HOST, IOS_SSH_PORT, IOS_SSH_USER, IOS_SSH_PASSWORD, IOS_SSH_KEY_FILE
    
    if hasattr(args, 'ssh_host') and args.ssh_host:
        IOS_SSH_HOST = args.ssh_host
    if hasattr(args, 'ssh_port') and args.ssh_port:
        IOS_SSH_PORT = args.ssh_port
    if hasattr(args, 'ssh_user') and args.ssh_user:
        IOS_SSH_USER = args.ssh_user
    if hasattr(args, 'ssh_password') and args.ssh_password:
        IOS_SSH_PASSWORD = args.ssh_password
    if hasattr(args, 'ssh_key_filename') and args.ssh_key_filename:
        IOS_SSH_KEY_FILE = args.ssh_key_filename
    
    # Execute the appropriate command
    if args.platform == 'android':
        if args.command == 'list-all':
            return 0 if list_android_packages(user_only=False) else 1
        elif args.command == 'list-user':
            return 0 if list_android_packages(user_only=True) else 1
        elif args.command == 'get-apk':
            return 0 if get_android_apk(args.package_name) else 1
        elif args.command == 'get-data':
            return 0 if get_android_data(args.package_name) else 1
    elif args.platform == 'ios':
        if args.command == 'list-all':
            return 0 if list_ios_applications() else 1
        elif args.command == 'get-ipa':
            return 0 if get_ios_ipa(args.package_name, args.output_name) else 1
        elif args.command == 'get-data':
            return 0 if get_ios_data(args.package_name) else 1
    
    return 0

if __name__ == '__main__':
    # Import threading here to avoid circular import
    import threading
    sys.exit(main())