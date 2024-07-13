import psutil
import time
import json
import os
import subprocess

def get_cpu_usage(process, interval=0.5):
    try:
        # Get CPU times at the start
        start_cpu = process.cpu_times()
        start_time = time.time()
        
        # Wait for the specified interval
        time.sleep(interval)
        
        # Get CPU times at the end
        end_cpu = process.cpu_times()
        end_time = time.time()
        
        # Calculate CPU usage
        cpu_percent = ((end_cpu.user - start_cpu.user) + (end_cpu.system - start_cpu.system)) / (end_time - start_time) * 100
        return cpu_percent
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def monitor_process(process, cpu_threshold, ram_threshold):
    try:
        while True:
            # Measure CPU usage
            cpu_usage = get_cpu_usage(process)
            if cpu_usage is None:
                print(f"Unable to measure CPU usage for process {process.pid}")
                return

            # Measure RAM usage
            ram_usage = process.memory_info().rss / (1024 * 1024)  # Convert bytes to MB
            
            print(f"Process Name: {process.name()} | Process ID: {process.pid} | CPU Usage: {cpu_usage:.2f}% | RAM Usage: {ram_usage:.2f} MB")
            
            # Take action if CPU usage exceeds the threshold
            if cpu_usage > cpu_threshold:
                print(f"High CPU usage detected for process {process.pid}! Taking action...")
                # Add your action here, e.g., terminate the process
                process.terminate()
                break
            
            # Take action if RAM usage exceeds the threshold
            if ram_usage > ram_threshold:
                print(f"High RAM usage detected for process {process.pid}! Taking action...")
                # Add your action here
                process.terminate()
                break

            time.sleep(0.5)  # Adjust the sleep time as needed
    except psutil.NoSuchProcess:
        print(f"Process with PID {process.pid} not found.")
        return

# Function to find processes by their executable path
def find_processes_by_path(path):
    processes = []
    normalized_path = os.path.normpath(path)
    for proc in psutil.process_iter(['pid', 'exe']):
        try:
            if proc.info['exe'] and os.path.normpath(proc.info['exe']) == normalized_path:
                processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes

# Main function to monitor multiple processes by their executable paths
def main():
    # Load configurations from config.json
    with open('config.json', 'r') as config_file:
        config = json.load(config_file)
    
    exe_paths_to_monitor = config['exe_paths_to_monitor']
    cpu_threshold = config['cpu_threshold']
    ram_threshold = config['ram_threshold']

    for exe_path in exe_paths_to_monitor:
        while True:
            processes = find_processes_by_path(exe_path)
            if processes:
                for process in processes:
                    monitor_process(process, cpu_threshold, ram_threshold)
                break  # Break the loop if at least one process is found
            else:
                print(f"No running process found with the path {exe_path}. Starting the process...")
                dir_name = os.path.dirname(exe_path)
                subprocess.run([exe_path], check=True, cwd=dir_name, creationflags=subprocess.CREATE_NEW_CONSOLE)
                time.sleep(5)  # Give some time for the process to start

if __name__ == "__main__":
    main()
