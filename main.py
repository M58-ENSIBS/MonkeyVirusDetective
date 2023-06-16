import exiftool
import re
import hashlib
import requests
import json
from tabulate import tabulate
import magic
import sys
import os
import subprocess
import re
from termcolor import colored


headers = {
    "accept": "application/json",
    "x-apikey": "Your_API_key"
}

try :
    file_path = sys.argv[1]
except IndexError:
    print("Please specify a file path")
    sys.exit(1)



OS = re.compile(r"Windows|Linux|MacOS", re.IGNORECASE)
Linux_Distribution = re.compile(r"(?i)(?:\b|(?<=\s))(Ubuntu|Debian|CentOS|Fedora|RedHat|ArchLinux|Kali|Parrot|Alpine|Gentoo|OpenSUSE|Slackware|Manjaro|LinuxMint|Zorin|Elementary|Solus|FreeBSD|OpenBSD|NetBSD|DragonFlyBSD|TrueOS|GhostBSD|HardenedBSD|MidnightBSD|macOS|iOS|watchOS|tvOS|iPadOS|Android|ChromeOS)(?=\s|\b)")
Ubuntu_Version = re.compile(r"Ubuntu (\d+\.\d+\.\d+)", re.IGNORECASE)
File = re.compile(r"\.c(?!\w)|\.cpp(?!\w)|\.exe(?!\w)", re.IGNORECASE)



def is_binary(file_path):
    """Function to check if a file is binary or not

    Args:
        file_path (str): Path to the file

    Returns:
        bool: True if the file is binary, False otherwise
    """
    try:
        with open(file_path, "rb") as file:
            content = file.read()
    except OSError:
        return True

    if any(pattern in content for pattern in [b"\x7fELF", b"MZ", b"PE\x00\x00", b"\x00\x61\x73\x6D"]):
        return True

    if file_path.endswith((".exe", ".dll")):
        return True

    try:
        file_type = magic.from_file(file_path)
    except OSError:
        return True
    if any(type_check in file_type for type_check in ["ELF", "PE32"]):
        return True

    if b"\xef\xbf\xbd" in content:
        return True

    return False



def get_metadata(file_path):
    """Function to get metadata of a file

    Args:
        file_path (str): Path to the file

    Returns:
        list: List of lists containing metadata
    """
    with exiftool.ExifTool() as et:
        metadata = et.get_metadata_batch([file_path])

    if metadata:
        try:
            metadata_table = [["File Size", "File Name", "File Type", "File Modify Date"]]
            for data in metadata:
                file_size = data.get("File:FileSize")
                file_name = data.get("File:FileName")
                file_type = data.get("File:FileType")
                file_modify_date = data.get("File:FileModifyDate")
                metadata_table.append([file_size, file_name, file_type, file_modify_date])
            return metadata_table
        except KeyError:
            return "No metadata found"
    else:
        return "No metadata found"


def get_decoded_content(file_path):
    """Function to get decoded content of a file

    Args:
        file_path (str): Path to the file

    Raises:
        ValueError: If the file cannot be decoded with any of the encodings

    Returns:
        str: Decoded content of the file
    """
    with open(file_path, "rb") as file:
        content = file.read()
        encodings = ["utf-8", "latin-1", "ascii"]  # Add more encodings if necessary
        decoded_content = None
        for encoding in encodings:
            try:
                decoded_content = content.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        if decoded_content is None:
            raise ValueError(f"Could not decode file {file_path} with any of the encodings {encodings}.")
        return decoded_content


def get_additional_info(decoded_content):
    """Function to get additional information from the decoded content of a file

    Args:
        decoded_content (str): Decoded content of the file

    Returns:
        list: List of lists containing additional information
    """
    additional_info_table = [["OS", ", ".join(set(OS.findall(decoded_content)))],
                             ["Linux Distribution", ", ".join(set(Linux_Distribution.findall(decoded_content)))],
                             ["Ubuntu Version", ", ".join(set(Ubuntu_Version.findall(decoded_content)) or ["Not Found"])],
                             ["File", ", ".join(set(File.findall(decoded_content)))],
                             ["isStripped", "False" if "not stripped" in subprocess.check_output(["file", file_path]).decode("utf-8") else "True"]]

    return additional_info_table


def get_virus_total_results(content):
    """Function to get VirusTotal results of a file

    Args:
        content (str): Content of the file

    Returns:
        dict: Dictionary containing VirusTotal results
    """
    content_encoded = content.encode("utf-8") 
    hash_md5 = hashlib.md5(content_encoded).hexdigest()
    url = "https://www.virustotal.com/api/v3/files/" + hash_md5

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        data = json_response.get("data")
        attributes = data.get("attributes")
        last_analysis_stats = attributes.get("last_analysis_stats")
        last_analysis_results = attributes.get("last_analysis_results")
        last_analysis_results_table = []
        for key, value in last_analysis_results.items():
            last_analysis_results_table.append([key, value.get("category"), value.get("result")])

        virus_total_results = {
            "virus_total_results": last_analysis_results_table,
            "virus_total_stats": {
                "Harmless": last_analysis_stats.get("harmless"),
                "Malicious": last_analysis_stats.get("malicious"),
                "Suspicious": last_analysis_stats.get("suspicious"),
                "Timeout": last_analysis_stats.get("timeout"),
                "Undetected": last_analysis_stats.get("undetected"),
                "Type Unsupported": last_analysis_stats.get("type-unsupported"),
                "Failure": last_analysis_stats.get("failure")
            }
        }
        return virus_total_results
    elif response.status_code == 404:
        return "Unknown file"
    else:
        return "Error: " + str(response.status_code)

def generate_json_output(metadata, additional_info, virus_total_results):
    """Function to generate JSON output

    Args:
        metadata (str): Metadata of the file
        additional_info (str): Additional information of the file
        virus_total_results (str): VirusTotal results of the file

    Returns:
        str: JSON output
    """
    result = {
        "metadata": metadata,
        "additional_info": additional_info,
        "virus_total_results": virus_total_results
    }
    result_json = json.dumps(result, indent=4)
    return result_json


def return_protection_of_file(file_path):
    """Function to return protection of a file

    Args:
        file_path (str): Path to the file

    Returns:
        list: List of lists containing protection information
    """
    try:
        output = subprocess.check_output(["checksec", "--file", file_path], stderr=subprocess.STDOUT)
        output = output.decode("utf-8")
        output = output.split("\n")
        output = [line.split() for line in output]
        output = [line for line in output if line]
        output = output[1:]
        for line in output:
            del line[0]
        output[2][0] = output[2][0] + " " + output[2][1]
        del output[2][1]
        return output
    except subprocess.CalledProcessError as e:
        print("Error:", e.output.decode("utf-8"))
        return []
    

def summarize_binary_behavior(file_path):
    """Function to summarize binary behavior

    Args:
        file_path (str): Path to the file

    Returns:
        list: List of lists containing summarized binary behavior
    """
    import subprocess
    def check_file_access(file_path):
        print("Send 'Enter' twice to continue")

        try:
            
            output = subprocess.check_output(["strace", "-e", "file", file_path], stderr=subprocess.STDOUT)
            output = output.decode("utf-8")

            file_access_regex = re.compile(r"openat\(AT_FDCWD, \".*\", .*")
            file_access_regex2 = re.compile(r"access\(.*\)")
            file_accesses = file_access_regex.findall(output)
            file_accesses2 = file_access_regex2.findall(output)
            file_accesses.extend(file_accesses2)
            return file_accesses
        except subprocess.CalledProcessError:
            return "Error"

    def check_subprocess_creation(file_path):
        """Function to check subprocess creation

        Args:
            file_path (str): Path to the file

        Returns:
            list: List of subprocesses
        """
        try:
            output = subprocess.check_output(["strace", "-f", "-e", "execve", "-s", "10000", file_path], stderr=subprocess.STDOUT)
            output = output.decode("utf-8")

            # Search for subprocess creations in the strace output
            subprocess_regex = re.compile(r"execve\((.*?)\)")
            subprocesses = subprocess_regex.findall(output)
            return subprocesses
        except subprocess.CalledProcessError:
            return "Error"

    file_accesses = check_file_access(file_path)
    subprocesses = check_subprocess_creation(file_path)

    summary = f"Binary Summary: {file_path}\n"
    summary += "=" * 50 + "\n"

    if file_accesses != "Error":
        summary += "File Accesses:\n"
        if file_accesses:
            for access in file_accesses:
                summary += f"  - {access}\n"
        else:
            summary += "No file accesses found.\n"
        summary += "\n"

    if subprocesses != "Error":
        summary += "Subprocess Creations:\n"
        if subprocesses:
            for subprocess in subprocesses:
                summary += f"  - {subprocess}\n"
        else:
            summary += "No subprocess creations found.\n"
        summary += "\n"

    output = summary
    return output



def parse_function(functions):
    """Function to parse functions

    Args:
        functions (list): List of functions

    Returns:
        list: List of parsed functions
    """
    functions_list = []
    for function in functions:
        function = function.replace("Non-debugging symbols:", "")
        function = function.split(" ")[-1]
        if not function.startswith("_"):
            if not function.endswith("_clones") and not function.endswith("_dummy"):
                for line in function:
                    if line == "":
                        function.remove(line)
                if function != "":
                    print("  - " + function)
                    functions_list.append(function)
    print("")
    return functions_list


def disassemble_function(function):
    """Function to disassemble a function

    Args:
        function (str): Function to disassemble

    Returns:
        list: List of disassembled function
    """
    try:
        output = subprocess.check_output(["gdb", "-batch", "-ex", "python import sys; sys.path.insert(0, '')", "-ex", "python import gdb; gdb.execute('file " + file_path + "')", "-ex", "python import gdb; print(gdb.execute('disassemble " + function + "', to_string=True))"], stderr=subprocess.STDOUT)
        disassembly_output = output.decode("utf-8")
        disassembly_list = disassembly_output.splitlines()[1:]  # Skip the first line (header)
        return disassembly_list
    except subprocess.CalledProcessError:
        return []
    

def list_functions_in_binary(file_path):
    """Function to list functions in a binary

    Args:
        file_path (str): Path to the file

    Returns:
        list: List of functions in the binary
    """
    try:
        output = subprocess.check_output(["gdb", "-batch", "-ex", "python import sys; sys.path.insert(0, '')", "-ex", "python import gdb; gdb.execute('file " + file_path + "')", "-ex", "python import gdb; print(gdb.execute('info functions', to_string=True))"], stderr=subprocess.STDOUT)
        functions_output = output.decode("utf-8")
        functions_list = functions_output.splitlines()[1:]  # Skip the first line (header)
        return functions_list
    except subprocess.CalledProcessError:
        return []


if is_binary(file_path):
    """Function to check if a file is a binary
    """
    metadata = get_metadata(file_path)
    print("Checksec output:")
    protection_info = return_protection_of_file(file_path)
    table = tabulate(protection_info, headers=["Security Aspect", "Status"], tablefmt="pipe")
    table = table.replace("found", colored("Found", "green"))
    table = table.replace("enabled", colored("Enabled", "red"))
    print(table)
    decoded_content = get_decoded_content(file_path)
    additional_info = get_additional_info(decoded_content)
    virus_total_results = get_virus_total_results(decoded_content)
    json_output = generate_json_output(metadata, additional_info, virus_total_results)
    print(json_output)
    file_accesses = summarize_binary_behavior(file_path)
    print(f"File accesses: {file_accesses}")
    functions = list_functions_in_binary(file_path)
    print(f"Found functions:")
    functions_list = parse_function(functions)
    for function in functions_list:
        disassembly = disassemble_function(function)
        print(f"Disassembly for {function}:")
        if not disassembly:
            print("  - No disassembly found")
        for line in disassembly:
            print(f"  - {line}")
        print("")

    print("Checking for strcmp usage...")
    for function in functions_list:
        disassembly = disassemble_function(function)
        for line in disassembly:
            if "strcmp" in line:
                print(f"  - strcmp found in {function} at address {line.split()[0]}")
                print("")
    print("")
 
else:
    print("File is not binary")
