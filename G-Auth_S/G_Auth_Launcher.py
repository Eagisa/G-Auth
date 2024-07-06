import pyotp
import msvcrt
import qrcode
import os
import time
import json
import stdiomask
import re
import hashlib
from github import Github, BadCredentialsException
import random
import colorama
from colorama import Fore, Back, Style
colorama.init(autoreset=True)
from pathlib import Path
import wmi
import socket
import requests
from datetime import datetime
import pytz
import sys
from cryptography.fernet import Fernet
import pyperclip
import threading


def PTC():
    msvcrt.getch()

def Logo():
    print(Fore.LIGHTYELLOW_EX+r'''  ____              _         _   _     
 / ___|            / \  _   _| |_| |__  
| |  _   _____    / _ \| | | | __| '_ \ 
| |_| | |_____|  / ___ \ |_| | |_| | | |
 \____|         /_/   \_\__,_|\__|_| |_|
                                        
''')

#=========================================================#
Access_Token = "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"
#=========================================================#

def get_google_time():
    try:
        response = requests.get('http://worldtimeapi.org/api/timezone/Etc/UTC')
        if response.status_code == 200:
            data = response.json()
            utc_datetime_str = data['datetime']
            # Correct the timezone offset format if necessary
            if utc_datetime_str[-3] == ':':
                utc_datetime_str = utc_datetime_str[:-3] + ':00'
            utc_datetime = datetime.fromisoformat(utc_datetime_str)
            return utc_datetime
        else:
            print(f"Failed to get time. HTTP Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def get_formatted_google_time():
    google_time = get_google_time()
    if google_time:
        ist_timezone = pytz.timezone('Asia/Kolkata')
        ist_time = google_time.astimezone(ist_timezone)
        formatted_time = ist_time.strftime('%m/%d/%Y %I:%M:%S %p').lstrip('0').replace('/0', '/')
        return formatted_time
    return None

formatted_time = get_formatted_google_time()

def SignUpPage():
    # Initialize GitHub instance
    g = Github(Access_Token)
    repo = g.get_user().get_repo("Auth-Database")
    file_path = "Accounts.json"

    # Fetch data once at the beginning
    def fetch_data():
        file_content = repo.get_contents(file_path).decoded_content.decode()
        return json.loads(file_content)

    # Update data function
    def update_data(data):
        file_content = repo.get_contents(file_path)
        repo.update_file(file_path, formatted_time, json.dumps(data, indent=4), file_content.sha)

    # Generate a unique 8-digit ID
    def generate_unique_id(existing_ids):
        while True:
            new_id = random.randint(10000000, 99999999)
            if new_id not in existing_ids:
                return new_id

    # Validate username function
    def validate_username(username):
        return bool(re.match(r'^[a-zA-Z0-9_]+$', username))

    # Hash password function using SHA-256
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    # Generate and verify OTP secret key
    def generate_and_verify_secret():
        issuer = "G-Auth"
        
        # Generate the secret key
        secret = pyotp.random_base32()
        # Generate the QR code
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(username, issuer_name=issuer)
        qr = qrcode.make(uri)
        
        # Display the QR code
        qr.show()
        while True:
            os.system("cls")
            Logo()
            print("",Fore.BLACK + Back.LIGHTYELLOW_EX+" Authentication Set Up ",Fore.BLACK+"G\n")
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"Your secret key: {secret}\n")
            # Verify OTP
            otp = input(Fore.LIGHTYELLOW_EX + " OTP > ")
            if totp.verify(otp):
                return secret
            elif otp == "`":
                os.system("cls")
                SignUpPage()
            else:
                os.system("cls")
                Logo()
                print("",Fore.BLACK + Back.LIGHTYELLOW_EX+" Authentication Set Up ",Fore.BLACK+"G\n")
                print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + " > Invalid OTP!")
                time.sleep(1.5)

    # Sign-up function
    def sign_up(username, password, confirm_password, data):
        # Normalize username to lowercase
        username_lower = username.lower()

        # Collect all existing usernames in lowercase
        existing_usernames = {name.lower() for name in data.keys()}
        existing_ids = {user_data["Id"] for user_data in data.values()}

        if username_lower in existing_usernames:
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> Username already exists.\n")
            return False

        if not validate_username(username):
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> Invalid username. Only letters, numbers, and underscores are allowed. No spaces or special characters.\n")
            return False

        if password != confirm_password:
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> Passwords do not match.\n")
            return False

        # Generate unique 8-digit ID
        user_id = generate_unique_id(existing_ids)

        # Hash password
        hashed_password = hash_password(password)

        def get_cpu_id():
            c = wmi.WMI()
            for processor in c.Win32_Processor():
                return processor.ProcessorId.strip()

        def get_hardware_id():
            c = wmi.WMI()
            for disk in c.Win32_DiskDrive():
                return disk.SerialNumber.strip()

        def get_ip_address():
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            return ip_address

        def hash_text(text: str) -> str:
            # Create a SHA-256 hash object
            sha256 = hashlib.sha256()

            # Update the hash object with the bytes of the text
            sha256.update(text.encode('utf-8'))

            # Get the hexadecimal representation of the digest
            hashed_text = sha256.hexdigest()

            return hashed_text

        # Example usage
        cpu_id = hash_text(get_cpu_id())
        hardware_id = hash_text(get_hardware_id())
        ip_address = hash_text(get_ip_address())

        # Generate and verify the secret key
        secret_key = generate_and_verify_secret()
        if not secret_key:
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> (Error Code: 20) - OTP verification failed. Couldn't create account\n")
            return

        data[username] = {
            "Id": user_id,
            "Auth": True,
            "Secret_Key": secret_key,
            "Password": hashed_password,
            "AccAccess": True,
            "DeviceInfo": {
                "CPUID": cpu_id,
                "HWID": hardware_id,
                "IP": ip_address
            },
            "JoinDate": formatted_time
        }

        update_data(data)
        os.system("cls")
        Logo()
        print("",Fore.BLACK + Back.LIGHTYELLOW_EX+" Sign Up ",Fore.BLACK+"G\n")
        print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> User registered successfully.\n")
        time.sleep(1.5)
        os.system("cls")
        StarterMenu()

    os.system("cls")
    Logo()
    print("",Fore.BLACK + Back.LIGHTYELLOW_EX+" Sign Up ",Fore.BLACK+"G\n")
    # Fetch existing data once
    data = fetch_data()

    User = " Username > "
    Pass = " Password > "
    ress = " Re-Password > "
    # Prompt for user input
    username = input(Fore.LIGHTYELLOW_EX +User)
    if username == "`":
        os.system("cls")
        StarterMenu()
    print("")
    password = stdiomask.getpass(prompt=Fore.LIGHTYELLOW_EX+Pass, mask="*")
    print("")
    confirm_password = stdiomask.getpass(prompt=Fore.LIGHTYELLOW_EX+ress, mask="*")

    # Sign up the new user
    sign_up(username, password, confirm_password, data)

# Reset Password Form
#================================================================================================================================================#
# GitHub repository information
github_username = 'Eagisa'
github_token = Access_Token  # Generate a personal access token from GitHub
repository_name = 'Auth-Database'
file_name = 'Accounts.json'

# Function to hash a password using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to reset password
def reset_password(username, new_password):
    # Load JSON file from GitHub
    g = Github(github_token)
    repo = g.get_user().get_repo(repository_name)
    file_content = repo.get_contents(file_name)
    json_data = json.loads(file_content.decoded_content)

    # Normalize the case for comparison
    username_lower = username.lower()
    matching_key = next((k for k in json_data if k.lower() == username_lower), None)

    # Check if username exists
    if matching_key:
        # Get user's information using the original case
        user_info = json_data[matching_key]

        # Check if user has a secret key
        if user_info['Secret_Key'] is None or user_info['Secret_Key'] == "null":
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + "You don't have authentication turned on.\n")
            time.sleep(2)
        else:
            # Hash the new password
            hashed_password = hash_password(new_password)

            # Update password in JSON data
            user_info['Password'] = hashed_password

            # Get existing secret key
            secret_key = user_info['Secret_Key']
            
            # Save changes back to GitHub
            updated_content = json.dumps(json_data, indent=4)
            repo.update_file(file_name, "Password reset", updated_content, file_content.sha)

            # Notify user and ask for OTP verification
            totp = pyotp.TOTP(secret_key)
            while True:
                os.system("cls")
                Logo()
                print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Reset Password ",Fore.BLACK+"G\n")
                otp = input(Fore.LIGHTYELLOW_EX + " OTP > ")
                if totp.verify(otp):
                    os.system("cls")
                    Logo()
                    print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Reset Password ",Fore.BLACK+"G\n")
                    print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + "Successfully reset password complete!\n")
                    time.sleep(1.5)
                    os.system("cls")
                    StarterMenu()
                else:
                    os.system("cls")
                    Logo()
                    print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Reset Password ",Fore.BLACK+"G\n")
                    print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + "Invalid OTP\n")
                    time.sleep(1.5)
    else:
        os.system("cls")
        Logo()
        print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Reset Password ",Fore.BLACK+"G\n")
        print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + "Username doesn't exist.\n")
        time.sleep(1.5)
        Reset_Password_Process()

# Main function
def Reset_Password_Process():
    while True:
        os.system("cls")
        Logo()
        print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Reset Password ",Fore.BLACK+"G\n")
        user_entry = " Username > "
        new_passss = " New Password > "
        new_re_pas = " Re-enter new password > "
        username_req = input(Fore.LIGHTYELLOW_EX + user_entry).strip()
        if username_req == "`":
            os.system("cls")
            StarterMenu()
        print("")
        new_password = stdiomask.getpass(prompt=Fore.LIGHTYELLOW_EX + new_passss, mask="*")
        print("")

        # Verify new password
        new_password_confirm = stdiomask.getpass(prompt=Fore.LIGHTYELLOW_EX + new_re_pas, mask="*")
        if new_password != new_password_confirm:
            os.system("cls")
            Logo()
            print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Reset Password ",Fore.BLACK+"G\n")
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + "Passwords do not match. Password reset failed.\n")
            time.sleep(1.5)
        else:
            reset_password(username_req, new_password)
#================================================================================================================================================#

username = None
user_id = None

# SignInPage
#=========================================================================================================================================#
def SignInPage():
    # Function to read user data from GitHub
    def read_user_data_from_github(g, repo_name, file_path):
        try:
            repo = g.get_repo(repo_name)
            file_content = repo.get_contents(file_path)
            return json.loads(file_content.decoded_content.decode())
        except BadCredentialsException:
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> Error Code: 17\n")
            return None
        except Exception as e:
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> Server is offline, try again later...\n")
            return None

    # Function to check if username exists (case-insensitive)
    def check_username_exists(user_data, username_to_check):
        return username_to_check.lower() in [username.lower() for username in user_data.keys()]

    # Function to validate password
    def validate_password(user_data, username_to_check, password_to_check):
        encrypted_password = encrypt_password(password_to_check)
        original_username = next(username for username in user_data.keys() if username.lower() == username_to_check.lower())
        return user_data[original_username]['Password'] == encrypted_password

    # Function to hash a password using SHA-256
    def encrypt_password(password):
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    # Function to check if username is valid
    def is_valid_username(username):
        return re.match(r'^[\w]+$', username) is not None

    # Function to clear the console screen
    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')

    # Your GitHub token and repository details
    TOKEN = Access_Token  # Replace with your actual GitHub token
    REPO_NAME_1 = "Eagisa/Auth-Database"  # Replace with your GitHub username and repository name
    REPO_NAME_2 = "Auth-Database"
    FILE_PATH = "Accounts.json"
    USERNAME = "Eagisa"

    # Initialize GitHub instance
    g = Github(TOKEN)

    # Main login loop
    while True:
        clear_screen()
        Logo()
        print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Sign In ",Fore.BLACK+"G\n")
        global username_to_check
        username_to_check = input(Fore.LIGHTYELLOW_EX + " Username > ")
        print("")

        if username_to_check == "`":
            os.system("cls")
            StarterMenu()

        if "`" in username_to_check:
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> Invalid username. The character '`' is not allowed.\n")
            time.sleep(2.3)
            continue

        if not is_valid_username(username_to_check):
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> Invalid username. Only letters, digits, and underscores are allowed.\n")
            time.sleep(2.3)
            continue

        password_to_check = stdiomask.getpass(prompt=Fore.LIGHTYELLOW_EX + " Password > ", mask="*")

        user_data = read_user_data_from_github(g, REPO_NAME_1, FILE_PATH)

        if user_data is None:
            input(Fore.LIGHTYELLOW_EX + "Press Enter to try again...")
            continue

        if check_username_exists(user_data, username_to_check):
            if validate_password(user_data, username_to_check, password_to_check):
                original_username = next(username for username in user_data.keys() if username.lower() == username_to_check.lower())
                auth_checker = user_data[original_username]['Auth']
                global username
                global user_id

                username = original_username
                user_id = user_data[original_username]['Id']

                # Replace with your GitHub personal access token
                GITHUB_TOKEN = Access_Token
                REPO_NAME = 'Auth-Database'
                FILE_PATH = 'Accounts.json'

                # Initialize GitHub object
                g = Github(GITHUB_TOKEN)
                repo = g.get_user().get_repo(REPO_NAME)
                file_content = repo.get_contents(FILE_PATH)
                user_data = json.loads(file_content.decoded_content.decode())

                # Function to get Auth and Secret_Key for a username
                def get_user_info(username):
                    if username in user_data:
                        user_info = user_data[username]
                        auth = user_info.get('Auth', False)
                        secret_key = user_info.get('Secret_Key')
                        return auth, secret_key
                    else:
                        print("Username not found")
                        return None, None

                # Replace with the username you want to check
                username_to_check = original_username

                auth_status, secret_key = get_user_info(username_to_check)

                if auth_status is None:
                    print(f"Username {username_to_check} not found.")
                    PTC()
                elif auth_status:
                    if secret_key:
                        while True:
                            os.system("cls")
                            Logo()
                            print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Sign In ",Fore.BLACK+"G\n")
                            entered_otp = input(Fore.LIGHTYELLOW_EX +" OTP > ")
                            totp = pyotp.TOTP(secret_key)
                            if totp.verify(entered_otp):
                                os.system("cls")
                                G_Auth_Main()
                            elif entered_otp == "`":
                                os.system("cls")
                                SignInPage()
                            else:
                                os.system("cls")
                                Logo()
                                print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Sign In ",Fore.BLACK+"G\n")
                                print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> Invalid OTP.\n")
                                time.sleep(1.5)
                    else:
                        print(f"No Secret Key for {username_to_check}")
                else:
                    os.system("cls")
                    G_Auth_Main()
            else:
                print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> Incorrect password.\n")
                time.sleep(1.5)
                continue
        else:
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> Username does not exist.\n")
            time.sleep(1.5)
            continue

#=========================================================================================================================================#

# G-Auth Main Program
#===================================================================================================================================================================================#
def G_Auth_Main():
    local_app_data = os.getenv('LOCALAPPDATA')
    folder_name = "G-Auth"
    version_file_path = Path(local_app_data) / folder_name / "version.txt"
    try:
        with open(version_file_path, "r") as file:
            version_id = file.read()
    except FileNotFoundError:
        print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> Error couldn't get the version, Restart the program.\n")
        PTC()
        exit()

    def title():
        global username
        global user_id

        if username == None and user_id == None:
            print("\n "+Fore.BLACK+Back.LIGHTRED_EX + f" G-Auth v{version_id} "," ",""+Fore.BLACK+Style.NORMAL+Back.LIGHTYELLOW_EX + " User ",Fore.LIGHTYELLOW_EX+"> {Not Found} ",Fore.BLACK+Style.NORMAL+Back.LIGHTYELLOW_EX + " ID ",Fore.LIGHTYELLOW_EX+"> {Not Found} ")
            print("\n")
        else:
            print("\n "+Fore.BLACK+Back.LIGHTRED_EX + f" G-Auth v{version_id} "," ",""+Fore.BLACK+Style.NORMAL+Back.LIGHTYELLOW_EX + " User ",Fore.LIGHTYELLOW_EX+f"> {username} ",Fore.BLACK+Style.NORMAL+Back.LIGHTYELLOW_EX + " ID ",Fore.LIGHTYELLOW_EX+f"> {user_id} ")
            print("\n")
    title()

    print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Home ",Fore.BLACK+"G\n\n")

    print("",Fore.BLACK + Back.LIGHTYELLOW_EX+" ? ", 
              Fore.LIGHTYELLOW_EX+"> Help \n\n",
              Fore.BLACK + Back.LIGHTYELLOW_EX+" 1 ", 
              Fore.LIGHTYELLOW_EX+"> AuthProfile \n\n",
              Fore.BLACK + Back.LIGHTYELLOW_EX+" 2 ", 
              Fore.LIGHTYELLOW_EX+"> AuthCodes\n")
    
    # AuthProfileCreatorPage
    #============================================================================================================================================================================================#
    def AuthProfileCreator():
        # Function to add a new game entry under a username and merge if the game exists
        def Add_Auth_Key(username, game, player_name, player_join_year, token, repo_name, github_path):
            # Load existing data from GitHub
            g = Github(token)
            repo = g.get_user().get_repo(repo_name)
            
            try:
                contents = repo.get_contents(github_path)
                data = json.loads(contents.decoded_content.decode())
            except:
                data = {}

            # Check if username already exists, otherwise initialize
            if username not in data:
                data[username] = []

            # Check if there's already an entry for the game
            existing_entry = next((item for item in data[username] if game in item), None)

            # If there's an existing entry, merge new data into it
            if existing_entry:
                existing_entry[game][player_name] = player_join_year
            else:
                # Otherwise, create a new entry
                new_entry = {
                    game: {
                        player_name: player_join_year
                    }
                }
                data[username].append(new_entry)

            # Convert data to JSON string
            json_data = json.dumps(data, indent=4)

            try:
                repo.update_file(contents.path, "Update AuthProfiles.json", json_data, contents.sha)
                print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> Successfully Added Secret Key.\n")
                time.sleep(1.5)
                os.system("cls")
            except:
                # If the file doesn't exist, create it
                repo.create_file(github_path, "Create AuthProfiles.json", json_data)
                print(f"Created {github_path} in {repo_name} repository.")


        # GitHub token and repository details
        token = Access_Token
        repo_name = "Auth-Database"
        github_path = "AuthProfiles.json"

        while True:
            title()
            print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Home ",Fore.LIGHTYELLOW_EX+">", Fore.BLACK + Back.LIGHTYELLOW_EX + " AuthProfile ",Fore.LIGHTYELLOW_EX+">",Fore.BLACK + Back.LIGHTYELLOW_EX + " Create AuthProfile ",Fore.BLACK+"G\n\n")
            print("",Fore.BLACK + Back.LIGHTYELLOW_EX+" 1 ",Fore.LIGHTYELLOW_EX+" Instragram | ",Fore.BLACK + Back.LIGHTYELLOW_EX+" 2 ",Fore.LIGHTYELLOW_EX+" Google  | ",Fore.BLACK + Back.LIGHTYELLOW_EX+" 3 ",Fore.LIGHTYELLOW_EX+" Twitter | ",Fore.BLACK + Back.LIGHTYELLOW_EX+" 4 ",Fore.LIGHTYELLOW_EX+" Roblox\n\n",
                Fore.BLACK + Back.LIGHTYELLOW_EX+" 5 ",Fore.LIGHTYELLOW_EX+" GitHub     |","",Fore.BLACK + Back.LIGHTYELLOW_EX+" 6 ",Fore.LIGHTYELLOW_EX+" Discord | ",Fore.BLACK + Back.LIGHTYELLOW_EX+" 7 ",Fore.LIGHTYELLOW_EX+" Reddit  | ",Fore.BLACK + Back.LIGHTYELLOW_EX+" 8 ",Fore.LIGHTYELLOW_EX+" Customize\n")
            choose_entry = input(Fore.LIGHTYELLOW_EX+" > ")

            if choose_entry == "1":
                site_insta = "Instragram"
                print("")
                User_ = input(Fore.LIGHTYELLOW_EX+f" Enter your {site_insta} username > ")
                if User_ == "`":
                    os.system("cls")
                    AuthProfileCreator()
                print("")
                secret_key = input(Fore.LIGHTYELLOW_EX+f" Enter your {User_} Secret Key > ")
                Add_Auth_Key(username, site_insta, User_, secret_key, token, repo_name, github_path)

            elif choose_entry == "2":
                site_Google = "Google"
                print("")
                User_ = input(Fore.LIGHTYELLOW_EX+f" Enter your {site_Google} username > ")
                if User_ == "`":
                    os.system("cls")
                    AuthProfileCreator()
                print("")
                secret_key = input(Fore.LIGHTYELLOW_EX+f" Enter your {User_} Secret Key > ")
                Add_Auth_Key(username, site_Google, User_, secret_key, token, repo_name, github_path)

            elif choose_entry == "3":
                site_Tweet = "Twitter"
                print("")
                User_ = input(Fore.LIGHTYELLOW_EX+f" Enter your {site_Tweet} username > ")
                if User_ == "`":
                    os.system("cls")
                    AuthProfileCreator()
                print("")
                secret_key = input(Fore.LIGHTYELLOW_EX+f" Enter your {User_} Secret Key > ")
                Add_Auth_Key(username, site_Tweet, User_, secret_key, token, repo_name, github_path)

            elif choose_entry == "4":
                site_blox = "Roblox"
                print("")
                User_ = input(Fore.LIGHTYELLOW_EX+f" Enter your {site_blox} username > ")
                if User_ == "`":
                    os.system("cls")
                    AuthProfileCreator()
                print("")
                secret_key = input(Fore.LIGHTYELLOW_EX+f" Enter your {User_} Secret Key > ")
                Add_Auth_Key(username, site_blox, User_, secret_key, token, repo_name, github_path)

            elif choose_entry == "5":
                site_Git = "GitHub"
                print("")
                User_ = input(Fore.LIGHTYELLOW_EX+f" Enter your {site_Git} username > ")
                if User_ == "`":
                    os.system("cls")
                    AuthProfileCreator()
                print("")
                secret_key = input(Fore.LIGHTYELLOW_EX+f" Enter your {User_} Secret Key > ")
                Add_Auth_Key(username, site_Git, User_, secret_key, token, repo_name, github_path)
            
            elif choose_entry == "6":
                site_DIs = "Discord"
                print("")
                User_ = input(Fore.LIGHTYELLOW_EX+f" Enter your {site_DIs} username > ")
                if User_ == "`":
                    os.system("cls")
                    AuthProfileCreator()
                print("")
                secret_key = input(Fore.LIGHTYELLOW_EX+f" Enter your {User_} Secret Key > ")
                Add_Auth_Key(username, site_DIs, User_, secret_key, token, repo_name, github_path)

            elif choose_entry == "7":
                site_Redd = "Reddit"
                print("")
                User_ = input(Fore.LIGHTYELLOW_EX+f" Enter your {site_Redd} username > ")
                if User_ == "`":
                    os.system("cls")
                    AuthProfileCreator()
                print("")
                secret_key = input(Fore.LIGHTYELLOW_EX+f" Enter your {User_} Secret Key > ")
                Add_Auth_Key(username, site_Redd, User_, secret_key, token, repo_name, github_path)

            elif choose_entry == "8":
                print("")
                website = input(Fore.LIGHTYELLOW_EX+" Enter site name >")
                if website == "`":
                    os.system("cls")
                    AuthProfileCreator()
                print("")
                User_ = input(Fore.LIGHTYELLOW_EX+" Enter a username > ")
                if User_ == "`":
                    os.system("cls")
                    AuthProfileCreator()
                print("")
                secret_key = input(Fore.LIGHTYELLOW_EX+" Enter the OTP Secret_key > ")
                Add_Auth_Key(username, website, User_, secret_key, token, repo_name, github_path)
            
            elif choose_entry == "`":
                os.system("cls")
                AuthProfilePage()
            
            else:
                print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> That was invalied.\n")
                time.sleep(1.5)
                os.system("cls")
    #============================================================================================================================================================================================#

    # AuthProfile Menu
    #===================================================================================================================================#
    def AuthProfilePage():
        title()
        print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Home ",Fore.LIGHTYELLOW_EX+">", Fore.BLACK + Back.LIGHTYELLOW_EX + " AuthProfile ",Fore.BLACK+"G\n\n")
        print("",Fore.BLACK + Back.LIGHTYELLOW_EX+" 1 ", 
        Fore.LIGHTYELLOW_EX+"> Create AuthProfile\n\n"
        "",Fore.BLACK + Back.LIGHTYELLOW_EX+" 2 ", 
        Fore.LIGHTYELLOW_EX+"> Remove AuthProfile\n")
        
        entry_Auth_Choice = input(Fore.LIGHTYELLOW_EX+" > ")
        if entry_Auth_Choice == "1":
            os.system("cls")
            AuthProfileCreator()
        elif entry_Auth_Choice == "2":
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> This feature is not available yet!\n")
            time.sleep(1.5)
            os.system("cls")
            AuthProfilePage()
        elif entry_Auth_Choice == "`":
            os.system("cls")
            G_Auth_Main()
        else:
            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> That was invalied.\n")
            time.sleep(1.5)
            os.system("cls")
            AuthProfilePage()
    #===================================================================================================================================#

    #AuthCodes Menu
    #=============================================================================================================#
    def AuthCodesPage():
        remaining_seconds = 0
        # Generate a key for encryption
        def generate_key():
            return Fernet.generate_key()

        # Encrypt data
        def encrypt_data(data, key):
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data.encode())
            return encrypted_data

        # Decrypt data
        def decrypt_data(encrypted_data, key):
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data).decode()
            return decrypted_data

        # Save the encryption key to a file
        def save_key(key, folder_name, key_file_name):
            try:
                local_app_data = os.getenv('LOCALAPPDATA')
                target_dir = os.path.join(local_app_data, folder_name)
                os.makedirs(target_dir, exist_ok=True)
                key_path = os.path.join(target_dir, key_file_name)

                with open(key_path, 'wb') as f:
                    f.write(key)

                return key_path

            except Exception as e:
                print(f'Error saving encryption key: {e}')
                return None

        # Load the encryption key from a file
        def load_key(folder_name, key_file_name):
            try:
                local_app_data = os.getenv('LOCALAPPDATA')
                key_path = os.path.join(local_app_data, folder_name, key_file_name)

                with open(key_path, 'rb') as f:
                    key = f.read()

                return key

            except Exception as e:
                print(f'Error loading encryption key: {e}')
                return None

        # Generate OTP using PyOTP
        def generate_otp(secret_key):
            try:
                totp = pyotp.TOTP(secret_key)
                otp_code = totp.now()
                return otp_code
            except Exception as e:
                print(f'Error generating OTP: {e}')
                return None

        # Retrieve data from GitHub repository
        def get_github_data(github_token, repo_name, file_path):
            try:
                g = Github(github_token)
                user = g.get_user()
                repo = user.get_repo(repo_name)
                file_contents = repo.get_contents(file_path).decoded_content.decode()
                data = json.loads(file_contents)
                return data

            except Exception as e:
                print(f'Error getting data from GitHub: {e}')
                return None

        # Save data to LocalAppData directory
        def save_data_to_localappdata(data, folder_name, file_name, key):
            try:
                local_app_data = os.getenv('LOCALAPPDATA')
                target_dir = os.path.join(local_app_data, folder_name)
                os.makedirs(target_dir, exist_ok=True)
                file_path = os.path.join(target_dir, file_name)

                encrypted_data = encrypt_data(json.dumps(data), key)

                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)

                return file_path

            except Exception as e:
                print(f'Error saving data to LocalAppData: {e}')
                return None

        # Load data from LocalAppData directory
        def load_data_from_localappdata(folder_name, file_name, key):
            try:
                local_app_data = os.getenv('LOCALAPPDATA')
                file_path = os.path.join(local_app_data, folder_name, file_name)

                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()

                data = decrypt_data(encrypted_data, key)

                return json.loads(data)

            except Exception as e:
                print(f'Error loading data from LocalAppData: {e}')
                return None

        # Function to handle copying OTP and other choices
        def handle_copy_choice(key_dict, selected_name):
            global remaining_seconds

            while True:
                copy_choice = input(Fore.LIGHTYELLOW_EX+" > ")

                if copy_choice.isdigit() and 1 <= int(copy_choice) <= len(key_dict):
                    selected_key_name, secret_key = list(key_dict.items())[int(copy_choice) - 1]
                    otp_code = generate_otp(secret_key)

                    if otp_code:
                        print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> OTP for {selected_key_name}: {otp_code}")
                        pyperclip.copy(otp_code)
                        print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> OTP copied to clipboard!\n")

                        # Start the OTP timer
                        totp = pyotp.TOTP(secret_key)
                        remaining_seconds = totp.interval - time.time() % totp.interval

                        # Display and countdown the timer
                        while remaining_seconds > 0:
                            print(Fore.LIGHTYELLOW_EX+f" OTP Validation > {remaining_seconds}", end="\r")
                            time.sleep(1)
                            remaining_seconds -= 1

                        # Refresh console after timer completes
                        os.system("cls" if os.name == "nt" else "clear")

                    else:
                        print(f'Error generating OTP for {selected_key_name}')

                    break

                elif copy_choice == "clear":
                    os.system("cls")
                    handle_object_selection(selected_name, key_dict)

                elif copy_choice == "`":
                    os.system("cls")
                    AuthCodesPage()

                else:
                    print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> That was invalied.\n")
                    time.sleep(1.5)
                    os.system("cls" if os.name == "nt" else "clear")
                    handle_object_selection(selected_name, key_dict)

        # Function to handle object selection
        def handle_object_selection(selected_name, key_dict):
            global remaining_seconds
            while True:
                os.system("cls" if os.name == "nt" else "clear")
                title()
                print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Home ",Fore.LIGHTYELLOW_EX+">", Fore.BLACK + Back.LIGHTYELLOW_EX + " AuthCodes ",Fore.LIGHTYELLOW_EX+">",Back.LIGHTYELLOW_EX+Fore.BLACK+f" {selected_name} ",Fore.BLACK+"G\n\n")
                for idx, (key_name, secret_key) in enumerate(key_dict.items(), start=1):
                    otp_code = generate_otp(secret_key)
                    if otp_code:
                        print("",Fore.BLACK + Back.LIGHTYELLOW_EX+f" {idx} ",Fore.LIGHTYELLOW_EX+f"> {key_name}\n")
                    else:
                        print(f" {idx} {key_name} Error generating OTP for {key_name}\n")

                handle_copy_choice(key_dict, selected_name)

        # Function to manage authentication codes page
        def AuthCodesPage():
            global remaining_seconds

            github_token = Access_Token
            repo_name = 'Auth-Database'
            github_file_path = 'AuthProfiles.json'
            local_folder_name = 'G-Auth'
            local_file_name = 'John_Doe.json'
            key_file_name = 'G-Data.key'

            title()

            print("", Fore.BLACK + Back.LIGHTYELLOW_EX + " Home ",Fore.LIGHTYELLOW_EX+">", Fore.BLACK + Back.LIGHTYELLOW_EX + " AuthCodes ",Fore.BLACK+"G\n\n")

            try:
                # Generate or load the encryption key
                key_path = os.path.join(os.getenv('LOCALAPPDATA'), local_folder_name, key_file_name)

                if not os.path.exists(key_path):
                    key = generate_key()
                    save_key(key, local_folder_name, key_file_name)
                else:
                    key = load_key(local_folder_name, key_file_name)

                # Download and save JSON data from GitHub
                data = get_github_data(github_token, repo_name, github_file_path)

                if data and username in data:
                    john_doe_data = {username: data[username]}
                    save_data_to_localappdata(john_doe_data, local_folder_name, local_file_name, key)
                else:
                    print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> You don't have AuthProfiles created.\n")
                    time.sleep(1.5)
                    os.system("cls")
                    G_Auth_Main()

                # Load data from LocalAppData
                local_data = load_data_from_localappdata(local_folder_name, local_file_name, key)

                if local_data:
                    john_doe_objects = local_data.get(username, [])
                    object_info = [(list(obj.keys())[0], list(obj.values())[0]) for obj in john_doe_objects]

                    for idx, (name, key_dict) in enumerate(object_info, start=1):
                        print("", Fore.BLACK + Back.LIGHTYELLOW_EX + f" {idx} ", Fore.LIGHTYELLOW_EX + f"> {name}\n")

                    choice_obj = input(Fore.LIGHTYELLOW_EX + " > ")

                    if choice_obj == "`":
                        os.system("cls")
                        G_Auth_Main()
                    elif choice_obj.isdigit():
                        choice_obj = int(choice_obj)
                        if 1 <= choice_obj <= len(object_info):
                            selected_name, key_dict = object_info[choice_obj - 1]
                            handle_object_selection(selected_name, key_dict)
                        else:
                            print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> That was invalied.\n")
                            time.sleep(1.5)
                    else:
                        print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> That was invalied.\n")
                        time.sleep(1.5)

                else:
                    print("Failed to load data from LocalAppData.")

            except Exception as e:
                print(f'Error: OOF')

        AuthCodesPage()
    #=============================================================================================================#

    #G-Auth main menu
    #=================================================================================================================================================================================#
    def main():
        entry = input(Fore.LIGHTYELLOW_EX+" > ")
        while True:
            if entry == "1":
                os.system("cls")
                AuthProfilePage()
            elif entry == "2":
                os.system("cls")
                AuthCodesPage()
            elif entry == "?":
                os.system("cls")
                Logo()
                print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> G-Auth is a unofficial program, Aka - (Google Authenticator) for windows only.\n")
                PTC()
                os.system("cls")
                G_Auth_Main()
            
            elif entry == "`":
                print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> Are you sure, to Sign Out? (Yes/No)?\n")
                
                choice = input(Fore.LIGHTYELLOW_EX+" > ").strip()

                if choice == "yes" or choice == "y":
                    os.system("cls")
                    StarterMenu()
                else:
                    os.system("cls")
                    G_Auth_Main()
            else:
                print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> That was invalied.\n")
                time.sleep(1.5)
                os.system("cls")
                G_Auth_Main()
    main()
    #=================================================================================================================================================================================#
#===================================================================================================================================================================================#

#Startermenu 
#=============================================================================================================================#
def StarterMenu():
        Version_Generator()
        Logo()
        print("",Fore.BLACK + Back.LIGHTYELLOW_EX+" 1 ", 
              Fore.LIGHTYELLOW_EX+" Sign In | ",
              Fore.BLACK + Back.LIGHTYELLOW_EX+" 2 ",Fore.LIGHTYELLOW_EX+" Sign Up | ",
              Fore.BLACK + Back.LIGHTYELLOW_EX+" 3 ",
              Fore.LIGHTYELLOW_EX+" Reset Password | ",
              Fore.BLACK + Back.LIGHTYELLOW_EX+" 4 ",
              Fore.LIGHTYELLOW_EX+" Support Ticket\n")
        entry = input(Fore.LIGHTYELLOW_EX+" > ")

        while True:
            # Login Page
            if entry == "1":
                SignInPage()
            # Sign Up Page
            elif entry == "2":
                SignUpPage()
            elif entry == "3":
                Reset_Password_Process()
            elif entry == "4":
                print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> This feature is not available yet!\n")
                time.sleep(1.5)
                os.system("cls")
                StarterMenu()
            else:
                print("\n", Fore.BLACK + Back.LIGHTGREEN_EX + " G-Auth ", Fore.LIGHTYELLOW_EX + f"> That was invalied.\n")
                time.sleep(1.5)
                os.system("cls")
                StarterMenu()
#=============================================================================================================================#

#============================================================================#
def Version_Generator():
    text_to_write = "12.1.0"
    local_app_data = os.getenv('LOCALAPPDATA')
    folder_name = "G-Auth"
    version_file_path = Path(local_app_data) / folder_name / "version.txt"
    if not os.path.exists(version_file_path.parent):
        os.makedirs(version_file_path.parent)
    with open(version_file_path, "w") as file:
        file.write(text_to_write)
#============================================================================#

if __name__ == "__main__":
    # Create threads
    Start_menu = threading.Thread(target=StarterMenu)
    VersionGen = threading.Thread(target=Version_Generator)
    # Start threads
    Start_menu.start()
    VersionGen.start()
    # Wait for both threads to complete
    Start_menu.join()
    VersionGen.join()

