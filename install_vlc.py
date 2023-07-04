import requests
import hashlib
import os
import subprocess

def main():

    # Get the expected SHA-256 hash value of the VLC installer
    expected_sha256 = get_expected_sha256()

    # Download (but don't save) the VLC installer from the VLC website
    installer_data = download_installer()

    # Verify the integrity of the downloaded VLC installer by comparing the
    # expected and computed SHA-256 hash values
    if installer_ok(installer_data, expected_sha256):
        
        # Save the downloaded VLC installer to disk
        installer_path = save_installer(installer_data)

        # Silently run the VLC installer
        run_installer(installer_path)

        # Delete the VLC installer from disk
        delete_installer(installer_path)

def get_expected_sha256():
    """Downloads the text file containing the expected SHA-256 value for the VLC installer file from the 
    videolan.org website and extracts the expected SHA-256 value from it.

    Returns:
        str: Expected SHA-256 hash value of VLC installer
    """
    # GET request to download file
    file_url = 'https://download.videolan.org/pub/videolan/vlc/3.0.18/win64/vlc-3.0.18-win64.exe.sha256'
    resp_msg = requests.get(file_url)

    # Verify download and retrieve hash value
    if resp_msg.status_code == requests.codes.ok:

        file_content = resp_msg.text

        hash_value = file_content.split(' ')

    return hash_value

def download_installer():
    """Downloads, but does not save, the .exe VLC installer file for 64-bit Windows.

    Returns:
        bytes: VLC installer file binary data
    """
    # GET request to download file
    file_url = 'https://download.videolan.org/pub/videolan/vlc/3.0.18/win64/vlc-3.0.18-win64.exe'
    resp_msg = requests.get(file_url)

    # Verify download and return installer data
    if resp_msg.status_code == requests.codes.ok:
        return resp_msg.content
    else:
        return

def installer_ok(installer_data, expected_sha256):
    """Verifies the integrity of the downloaded VLC installer file by calculating its SHA-256 hash value 
    and comparing it against the expected SHA-256 hash value. 

    Args:
        installer_data (bytes): VLC installer file binary data
        expected_sha256 (str): Expeced SHA-256 of the VLC installer

    Returns:
        bool: True if SHA-256 of VLC installer matches expected SHA-256. False if not.
    """    
    # Compare hash value of downloaded file to expected hash returning True if they match and False if they don't
    if hashlib.sha256(installer_data).hexdigest() == expected_sha256[0]:
        return True
    else:
        return False

def save_installer(installer_data):
    """Saves the VLC installer to a local directory.

    Args:
        installer_data (bytes): VLC installer file binary data

    Returns:
        str: Full path of the saved VLC installer file
    """
    # Saves installer to temp directory and returns full path as a string
    path = r'C:\temp\VLC.exe'
    with open(path, 'wb') as file:
        file.write(installer_data)
              
    return path

def run_installer(installer_path):
    """Silently runs the VLC installer.

    Args:
        installer_path (str): Full path of the VLC installer file
    """    
    subprocess.run([installer_path, '/L=1033', '/S'])

    return
    
def delete_installer(installer_path):
    """Deletes the VLC installer file.

    Args:
        installer_path (str): Full path of the VLC installer file
    """
    os.remove(installer_path)

    return

if __name__ == '__main__':
    main()