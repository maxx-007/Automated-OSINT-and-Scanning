import subprocess
import platform
import shutil
import os
import sys
from datetime import datetime  # Import datetime module to generate timestamps

def is_rustscan_installed():
    rustscan_path = shutil.which("rustscan")
    if rustscan_path:
        print(f"RustScan found at: {rustscan_path}")
    else:
        print("RustScan is not found.")
    return rustscan_path is not None

def install_rustscan():
    os_name = platform.system()
    if os_name == 'Linux':
        install_command = "sudo apt update && sudo apt install -y rustscan"
        try:
            result = subprocess.run(install_command, shell=True, check=True, capture_output=True, text=True)
            print("RustScan installed successfully.")
            print("Output:", result.stdout)
            print("Error:", result.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Error occurred while installing RustScan: {e}")
            print("Output:", e.stdout)
            print("Error:", e.stderr)
    else:
        print("This script is designed to run on Linux systems with apt package manager.")

def run_rustscan(target_ip, port_range="1-65535", batch_size=2000, ulimit=5000, timeout=2000, nmap_options="-sC -sV", script_options=None):
    command = ["rustscan", "-a", target_ip]

    # Add options to the command
    if port_range:
        command.extend(["-r", port_range])
    if batch_size:
        command.extend(["-b", str(batch_size)])
    if ulimit:
        command.extend(["--ulimit", str(ulimit)])
    if timeout:
        command.extend(["-t", str(timeout)])
    if nmap_options:
        command.extend(["--"])
        command.extend(nmap_options.split())
    if script_options:
        command.extend(script_options.split())

    print(f"Running command: {' '.join(command)}")

    # Create directory for the target IP with a timestamp
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    results_dir = os.path.join(target_ip + "_" + timestamp)  # Append timestamp to directory name
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    output_file = os.path.join(results_dir, f"{target_ip}_{timestamp}.txt")  # Include timestamp in file name
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=300)
        # Print and write output to file
        print(result.stdout)
        print(result.stderr)
        with open(output_file, "w") as file:
            file.write(result.stdout)
            file.write(result.stderr)
        print(f"Command executed: {' '.join(command)}")
        print("Output saved to:", output_file)
        print("Return code:", result.returncode)
    except subprocess.TimeoutExpired as e:
        print(f"Error: Command '{e.cmd}' timed out.")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while running RustScan: {e}")
        with open(output_file, "w") as file:
            file.write(e.stdout)
            file.write(e.stderr)
        print("Output saved to:", output_file)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <target_ip_or_website>")
        sys.exit(1)

    target_ip = sys.argv[1]

    if not is_rustscan_installed():
        print("RustScan is not installed. Installing now...")
        install_rustscan()

    if is_rustscan_installed():
        run_rustscan(target_ip)
    else:
        print("RustScan is not executable. Please ensure it is installed correctly.")

if __name__ == "__main__":
    main()

