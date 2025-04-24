import os
import platform
import socket
import psutil
import subprocess
import threading
from datetime import datetime
import requests
import argparse
import customtkinter as ctk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

# ---- API Key for CVE Lookup ----
NVD_API_KEY = "46da12d9-d107-421c-9303-d67aaf4c748d"

# ---- Initialize GUI ----
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.title("INSPECTRA - Security Scanner")
root.geometry("900x700")

# ---- Global Variables ----
scan_results = {}
start_port = 1
end_port = 1024
output_file = "scan_report.txt"

# ---- Helper Functions ----
def create_line(parent, width=400, height=2):
    """Create a horizontal line for visual separation"""
    line = ctk.CTkFrame(parent, width=width, height=height, fg_color=("gray80", "gray30"))
    return line

# ---- Function to Switch Pages ----
def show_page(page):
    """Switch between pages."""
    # Hide all pages
    for frame in [welcome_frame, home_frame, scan_loading_frame, results_frame]:
        if frame.winfo_exists():
            frame.pack_forget()
    
    # Show the requested page
    page.pack(pady=20, padx=20, fill="both", expand=True)

# ---- Backend Functions ----
def get_os_info():
    """Get OS version and architecture."""
    os_name = platform.system()
    os_version = platform.version()
    architecture = platform.architecture()[0]
    print(f"\n🖥 OS: {os_name} {os_version} ({architecture})")
    return os_name, os_version, architecture

def get_ip_info():
    """Get local IP address."""
    for iface, snics in psutil.net_if_addrs().items():
        for snic in snics:
            if snic.family == socket.AF_INET and not snic.address.startswith("127."):
                print(f"\n🌐 Local IP Address: {snic.address}")
                return snic.address
    return "127.0.0.1"

def scan_port(port, open_ports, host='127.0.0.1'):
    """Scan a single port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
    except:
        pass

def fast_scan_ports(host='127.0.0.1', start_port=1, end_port=1024, max_threads=100):
    """Multi-threaded function to scan ports quickly."""
    open_ports = []
    threads = []

    print(f"\n🔍 Scanning ports {start_port}-{end_port} on {host}...")

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(port, open_ports, host))
        threads.append(thread)
        thread.start()

        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()
    
    return sorted(open_ports)

def list_running_processes():
    """List running processes."""
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'] or "Unknown"
                processes.append(f"{name} (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        print(f"Error listing processes: {e}")
    
    return processes

def list_network_connections():
    """List active network connections."""
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            try:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                conn_info = f"{laddr} → {raddr} (Status: {conn.status})"
                connections.append(conn_info)
            except:
                continue
    except Exception as e:
        print(f"Error listing connections: {e}")
    
    return connections

def get_system_info():
    """Retrieve detailed system info."""
    try:
        if platform.system() == "Windows":
            sys_info = subprocess.getoutput("systeminfo")
        else:
            sys_info = subprocess.getoutput("uname -a")
        return sys_info
    except Exception as e:
        return f"Error retrieving system info: {e}"

def check_vulnerabilities(os_name, os_version, process_names):
    """Check for known vulnerabilities (CVE) for the detected OS and processes."""
    print("\n🚨 Checking for known vulnerabilities...")
    
    cve_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": NVD_API_KEY}
    
    seen = set()
    top_vulns = []
    existing_vulns = []

    # General OS vulnerabilities
    try:
        os_params = {
            "keywordSearch": f"{os_name} {os_version}",
            "resultsPerPage": 10
        }
        response = requests.get(cve_url, headers=headers, params=os_params, timeout=15)
        response.raise_for_status()
        data = response.json()
        for cve in data.get("vulnerabilities", []):
            cve_id = cve['cve']['id']
            desc = cve['cve']['descriptions'][0]['value']
            existing_vulns.append((cve_id, desc))
    except Exception as e:
        print(f"⚠ Error fetching OS CVEs: {e}")

    # Top CVEs for running software
    for name in process_names[:50]:  # Limit to first 50 processes
        name_cleaned = name.split(" ")[0].lower()
        if name_cleaned in seen or name_cleaned in ["system", "idle", "unknown"]:
            continue
        seen.add(name_cleaned)

        try:
            params = {
                "keywordSearch": name_cleaned,
                "resultsPerPage": 1
            }
            response = requests.get(cve_url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            cve_entries = data.get("vulnerabilities", [])
            if cve_entries:
                cve = cve_entries[0]
                cve_id = cve['cve']['id']
                description = cve['cve']['descriptions'][0]['value']
                top_vulns.append((name_cleaned, cve_id, description))
        except:
            continue

        if len(top_vulns) >= 10:
            break
            
    return existing_vulns, top_vulns

def save_results(filename, os_info, ip_info, open_ports, processes, connections, system_info, existing_vulns, top_vulns):
    """Save scan results to a file."""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("🔎 Local System Scan Report\n")
            f.write("="*40 + "\n")
            f.write(f"Timestamp: {datetime.now()}\n")
            f.write(f"OS: {os_info[0]} {os_info[1]}\n")
            f.write(f"Local IP Address: {ip_info}\n\n")
            
            f.write("Open Ports:\n")
            for port in open_ports:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown"
                f.write(f"Port {port} ({service})\n")
                
            f.write("\nRunning Processes:\n")
            f.write('\n'.join(processes[:100]) + "\n")
            if len(processes) > 100:
                f.write(f"... and {len(processes) - 100} more processes\n")
            
            f.write("\nNetwork Connections:\n")
            f.write('\n'.join(connections[:50]) + "\n")
            if len(connections) > 50:
                f.write(f"... and {len(connections) - 50} more connections\n")
            
            f.write("\nSystem Information:\n")
            f.write(system_info + "\n\n")

            f.write("Existing Vulnerabilities (OS-based):\n")
            for cve_id, desc in existing_vulns:
                f.write(f"- {cve_id}: {desc}\n")

            f.write("\nRunning Software Vulnerabilities:\n")
            for name, cve_id, desc in top_vulns:
                f.write(f"- {name}: {cve_id} — {desc}\n")
                
        return True
    except Exception as e:
        print(f"Error saving results: {e}")
        return False

def scan_system(start=1, end=1024, out_file="scan_report.txt", check_vuln=True, max_threads=50):
    """Perform a system vulnerability scan."""
    global scan_results
    scan_results = {}

    # Update scan progress
    scan_label.configure(text="Getting OS Info...")
    root.update()
    scan_progress.set(0.1)
    
    os_info = get_os_info()
    scan_results["OS Info"] = os_info
    
    scan_label.configure(text="Getting IP Address...")
    root.update()
    scan_progress.set(0.2)
    
    ip_info = get_ip_info()
    scan_results["IP Address"] = ip_info
    
    scan_label.configure(text=f"Scanning Ports {start}-{end}...")
    root.update()
    scan_progress.set(0.3)
    
    open_ports = fast_scan_ports('127.0.0.1', start, end, max_threads)
    scan_results["Open Ports"] = open_ports
    
    scan_label.configure(text="Listing Running Processes...")
    root.update()
    scan_progress.set(0.5)
    
    processes = list_running_processes()
    scan_results["Processes"] = processes
    
    scan_label.configure(text="Checking Network Connections...")
    root.update()
    scan_progress.set(0.7)
    
    connections = list_network_connections()
    scan_results["Connections"] = connections
    
    scan_label.configure(text="Getting System Info...")
    root.update()
    scan_progress.set(0.8)
    
    system_info = get_system_info()
    scan_results["System Info"] = system_info
    
    # Skip vulnerability checking if requested
    if not check_vuln:
        scan_label.configure(text="Skipping vulnerability checks as requested...")
        root.update()
        existing_vulns = []
        top_vulns = []
    else:
        scan_label.configure(text="Checking for Vulnerabilities...")
        root.update()
        scan_progress.set(0.9)
        
        process_names = [proc.split(" (PID")[0] for proc in processes]
        existing_vulns, top_vulns = check_vulnerabilities(os_info[0], os_info[1], process_names)
    
    scan_results["OS Vulnerabilities"] = existing_vulns
    scan_results["Software Vulnerabilities"] = top_vulns
    
    scan_label.configure(text="Saving Results...")
    root.update()
    save_success = save_results(
        out_file, os_info, ip_info, open_ports, processes, 
        connections, system_info, existing_vulns, top_vulns
    )
    
    if save_success:
        scan_label.configure(text="Scan Complete!")
    else:
        scan_label.configure(text="Scan Complete with Errors!")
    
    scan_progress.set(1.0)
    root.update()

    # Update results display
    root.after(1000, update_results_display)
    
    # Move to results page
    root.after(1000, lambda: show_page(results_frame))

# ---- GUI Pages ----
# 1. Welcome Page (Title Page)
welcome_frame = ctk.CTkFrame(root, fg_color="#272c30")

# Center the content vertically and horizontally
welcome_content = ctk.CTkFrame(welcome_frame, fg_color="#272c30")
welcome_content.pack(expand=True, fill="both")
welcome_content.grid_columnconfigure(0, weight=1)
welcome_content.grid_rowconfigure((0, 1, 2, 3), weight=1)

# App logo/icon
logo_frame = ctk.CTkFrame(
    welcome_content, 
    width=100, 
    height=100, 
    corner_radius=50,
    fg_color=("#1E88E5" if ctk.get_appearance_mode() == "light" else "#2979FF")
)
logo_frame.grid(row=1, column=0, pady=(0, 20))
logo_frame.grid_propagate(False)  # Keep the frame size fixed

# Add the cyber logo
image = Image.open("cyber_logo.png")  
image = image.resize((900, 900))  
photo = ImageTk.PhotoImage(image)

# Create a label to display the image
logo_label = ctk.CTkLabel(logo_frame,image=photo, text="")
logo_label.image = photo  # Keep a reference to prevent garbage collection
logo_label.pack()

# Start button
def go_to_home():
    show_page(home_frame)

welcome_button = ctk.CTkButton(
    welcome_content, 
    text="Get Started", 
    font=("Arial", 18, "bold"),
    height=50,
    width=200,
    corner_radius=10,
    command=go_to_home
)
welcome_button.grid(row=4, column=0, pady=(0, 50))

# 2. Home Page (Settings)
home_frame = ctk.CTkFrame(root)

# Header
header_frame = ctk.CTkFrame(home_frame, fg_color="transparent")
header_frame.pack(pady=(20, 30), fill="x")

header_title = ctk.CTkLabel(
    header_frame, 
    text="INSPECTRA", 
    font=("Arial", 36, "bold"),
    text_color=("#1E88E5" if ctk.get_appearance_mode() == "light" else "#64B5F6")
)
header_title.pack(pady=(0, 5))

header_subtitle = ctk.CTkLabel(
    header_frame,
    text="Configure Scan Settings",
    font=("Arial", 16),
    text_color=("gray60" if ctk.get_appearance_mode() == "light" else "gray70")
)
header_subtitle.pack(pady=(0, 10))

header_line = create_line(header_frame)
header_line.pack(pady=(0, 20))

# Settings container
settings_frame = ctk.CTkFrame(home_frame)
settings_frame.pack(pady=10, padx=20, fill="x")

# Port range settings
port_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
port_frame.pack(pady=10, padx=20, fill="x")

port_label = ctk.CTkLabel(port_frame, text="Port Range:", font=("Arial", 12, "bold"), width=120, anchor="w")
port_label.pack(side="left", padx=5)

start_port_var = ctk.StringVar(value="1")
start_port_entry = ctk.CTkEntry(port_frame, width=80, textvariable=start_port_var)
start_port_entry.pack(side="left", padx=5)

port_to_label = ctk.CTkLabel(port_frame, text="to")
port_to_label.pack(side="left", padx=5)

end_port_var = ctk.StringVar(value="1024")
end_port_entry = ctk.CTkEntry(port_frame, width=80, textvariable=end_port_var)
end_port_entry.pack(side="left", padx=5)

# Advanced options
advanced_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
advanced_frame.pack(pady=10, padx=20, fill="x")

skip_vuln_var = ctk.BooleanVar(value=False)
skip_vuln_check = ctk.CTkCheckBox(advanced_frame, text="Skip Vulnerability Checking", variable=skip_vuln_var)
skip_vuln_check.pack(side="left", padx=5)

max_threads_label = ctk.CTkLabel(advanced_frame, text="Max Threads:")
max_threads_label.pack(side="left", padx=(20, 5))

max_threads_var = ctk.StringVar(value="50")
max_threads_entry = ctk.CTkEntry(advanced_frame, width=50, textvariable=max_threads_var)
max_threads_entry.pack(side="left", padx=5)

# Output file setting
file_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
file_frame.pack(pady=(10, 15), padx=20, fill="x")

file_label = ctk.CTkLabel(file_frame, text="Output File:", font=("Arial", 12, "bold"), width=120, anchor="w")
file_label.pack(side="left", padx=5)

output_file_var = ctk.StringVar(value="scan_report.txt")
output_file_entry = ctk.CTkEntry(file_frame, width=250, textvariable=output_file_var)
output_file_entry.pack(side="left", padx=5)

# Start scan button
def start_system_scan():
    """Start the system scan with the specified settings."""
    global start_port, end_port, output_file
    
    # Validate port range
    try:
        start_port = int(start_port_var.get())
        end_port = int(end_port_var.get())
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError("Invalid port range")
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid port range (1-65535)")
        return
    
    # Validate max threads
    try:
        max_threads = int(max_threads_var.get())
        if max_threads < 1 or max_threads > 200:
            raise ValueError("Invalid thread count")
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid thread count (1-200)")
        return
    
    # Get output file
    output_file = output_file_var.get().strip()
    if not output_file:
        output_file = "scan_report.txt"
    
    # Check if we can write to the output file
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("Testing file write access\n")
    except Exception as e:
        messagebox.showerror("Error", f"Cannot write to output file: {e}")
        return
    
    # Update UI
    scan_progress.set(0)
    scan_label.configure(text="Preparing scan...")
    show_page(scan_loading_frame)
    
    # Start the scan in a separate thread
    def run_scan():
        try:
            scan_system(
                start=start_port, 
                end=end_port, 
                out_file=output_file,
                check_vuln=not skip_vuln_var.get(),
                max_threads=max_threads
            )
        except Exception as e:
            # Handle any unexpected errors
            scan_label.configure(text=f"Error: {str(e)}")
            scan_progress.set(0)
            messagebox.showerror("Scan Error", f"An error occurred during scanning: {e}")
            root.after(2000, lambda: show_page(home_frame))
    
    threading.Thread(target=run_scan).start()

start_button_frame = ctk.CTkFrame(home_frame, fg_color="transparent")
start_button_frame.pack(pady=(20, 20), fill="x")

start_button = ctk.CTkButton(
    start_button_frame, 
    text="🚀 START SCAN", 
    font=("Arial", 20, "bold"),
    height=50,
    corner_radius=10,
    command=start_system_scan
)
start_button.pack(pady=10, padx=100)

# Back button to return to welcome screen
back_button = ctk.CTkButton(
    home_frame, 
    text="← Back to Welcome", 
    font=("Arial", 14),
    corner_radius=8,
    command=lambda: show_page(welcome_frame)
)
back_button.pack(pady=(0, 10))

# 3. Loading Page (System Scan)
scan_loading_frame = ctk.CTkFrame(root)

loading_header = ctk.CTkFrame(scan_loading_frame, fg_color="transparent")
loading_header.pack(pady=(30, 10), fill="x")

loading_title = ctk.CTkLabel(
    loading_header, 
    text="SCANNING SYSTEM",
    font=("Arial", 28, "bold"),
    text_color=("#1E88E5" if ctk.get_appearance_mode() == "light" else "#64B5F6")
)
loading_title.pack(pady=(0, 10))

scan_label = ctk.CTkLabel(scan_loading_frame, text="Preparing scan...", font=("Arial", 16))
scan_label.pack(pady=20)

scan_progress_container = ctk.CTkFrame(scan_loading_frame, fg_color="transparent")
scan_progress_container.pack(pady=10)

scan_progress = ctk.CTkProgressBar(scan_progress_container, width=400, height=15, corner_radius=5)
scan_progress.pack(pady=10)
scan_progress.set(0)  # Initial progress

# Cancel button
def cancel_scan():
    if messagebox.askyesno("Cancel Scan", "Are you sure you want to cancel the scan?"):
        show_page(home_frame)

cancel_button = ctk.CTkButton(
    scan_loading_frame,
    text="Cancel Scan",
    font=("Arial", 14),
    corner_radius=8,
    command=cancel_scan
)
cancel_button.pack(pady=(20, 10))

# 4. Results Page
results_frame = ctk.CTkFrame(root, fg_color="#272c30")

# Results header
results_header = ctk.CTkFrame(results_frame, fg_color="transparent")
results_header.pack(pady=(20, 10), fill="x")

results_title = ctk.CTkLabel(
    results_header, 
    text="SCAN RESULTS",
    font=("Arial", 28, "bold"),
    text_color="#64B5F6"
)
results_title.pack(pady=(0, 5))

# Create main container for horizontal layout
main_container = ctk.CTkFrame(results_frame, fg_color="#1a1a1a")
main_container.pack(fill="both", expand=True, padx=0, pady=0)

# Configure main container to have 5 equal columns
for i in range(5):
    main_container.grid_columnconfigure(i, weight=1)

def create_visual_section(parent, title, content, icon="🔍"):
    """Create a visually appealing section"""
    section_frame = ctk.CTkFrame(parent, fg_color="#2b2b2b", corner_radius=0)
    
    # Section header
    header_frame = ctk.CTkFrame(section_frame, fg_color="#1e1e1e", corner_radius=0, height=40)
    header_frame.pack(fill="x", pady=0)
    header_frame.pack_propagate(False)  # Keep header height fixed
    
    title_label = ctk.CTkLabel(
        header_frame, 
        text=f"{icon} {title}",
        font=("Arial", 16, "bold"),
        text_color="#64B5F6"
    )
    title_label.pack(side="left", padx=10, pady=5)
    
    return section_frame

def create_scrollable_section(parent, title, icon, section_width):
    """Helper function to create a consistent scrollable section"""
    # Main frame
    frame = ctk.CTkFrame(parent, fg_color="#2b2b2b", corner_radius=0)
    frame.configure(width=section_width)
    frame.pack(side="left", fill="both", padx=1)
    frame.pack_propagate(False)
    
    # Header frame with fixed height
    header_frame = ctk.CTkFrame(frame, fg_color="#1e1e1e", corner_radius=0, height=40)
    header_frame.pack(fill="x", pady=0)
    header_frame.pack_propagate(False)
    
    # Title in header
    title_label = ctk.CTkLabel(
        header_frame,
        text=f"{icon} {title}",
        font=("Arial", 16, "bold"),
        text_color="#64B5F6"
    )
    title_label.pack(side="left", padx=10, pady=5)
    
    # Content area with proper background
    content_area = ctk.CTkFrame(frame, fg_color="#2b2b2b")
    content_area.pack(fill="both", expand=True, pady=0)
    
    # Scrollable canvas with proper background
    canvas = ctk.CTkCanvas(content_area, bg="#2b2b2b", highlightthickness=0)
    scrollbar = ctk.CTkScrollbar(content_area, orientation="vertical", command=canvas.yview)
    
    # Content frame inside canvas with proper background
    content_frame = ctk.CTkFrame(canvas, fg_color="#2b2b2b")
    
    # Configure scrolling
    canvas.bind('<Enter>', lambda e: canvas.bind_all("<MouseWheel>", lambda e: _on_mousewheel(e, canvas)))
    canvas.bind('<Leave>', lambda e: canvas.unbind_all("<MouseWheel>"))
    
    # Create window for content frame
    canvas_window = canvas.create_window((0, 0), window=content_frame, anchor="nw")
    
    # Update scroll region when content changes
    def configure_scroll_region(event):
        canvas.configure(scrollregion=canvas.bbox("all"))
        # Make sure the content frame fills the canvas width
        canvas.itemconfig(canvas_window, width=canvas.winfo_width())
        
    def configure_canvas(event):
        # Update canvas width when window resizes
        canvas.itemconfig(canvas_window, width=canvas.winfo_width())
        
    content_frame.bind("<Configure>", configure_scroll_region)
    canvas.bind("<Configure>", configure_canvas)
    
    # Configure canvas scroll
    canvas.configure(yscrollcommand=scrollbar.set)
    
    # Pack canvas and scrollbar
    canvas.pack(side="left", fill="both", expand=True, padx=(5, 0))
    scrollbar.pack(side="right", fill="y")
    
    # Create an inner frame for content with padding
    inner_frame = ctk.CTkFrame(content_frame, fg_color="#2b2b2b")
    inner_frame.pack(fill="both", expand=True, padx=10)
    
    return inner_frame

def _on_mousewheel(event, canvas):
    canvas.yview_scroll(int(-1*(event.delta/120)), "units")

def update_results_display():
    """Update the results display with organized sections"""
    # Clear existing content
    for widget in results_frame.winfo_children():
        widget.destroy()
    
    # Set the window size to maximize and configure results frame
    root.state('zoomed')
    results_frame.configure(fg_color="#1a1a1a")
    
    # Get open ports from scan results
    open_ports = scan_results.get("Open Ports", [])
    
    # Create top half container
    top_container = ctk.CTkFrame(results_frame, fg_color="#1a1a1a", corner_radius=0)
    top_container.pack(fill="both", expand=True, pady=(0, 5))
    
    # Create vulnerabilities section in place of security score
    vuln_frame = ctk.CTkFrame(top_container, fg_color="#2b2b2b", corner_radius=0)
    vuln_frame.pack(side="left", fill="both", expand=True, padx=1)
    
    # Vulnerabilities header
    vuln_header = ctk.CTkFrame(vuln_frame, fg_color="#1e1e1e", corner_radius=0, height=40)
    vuln_header.pack(fill="x", pady=0)
    vuln_header.pack_propagate(False)
    
    vuln_title = ctk.CTkLabel(
        vuln_header,
        text="🛡️ System Vulnerabilities",
        font=("Arial", 20, "bold"),
        text_color="#64B5F6"
    )
    vuln_title.pack(pady=5)
    
    # Vulnerabilities content
    vuln_content = ctk.CTkFrame(vuln_frame, fg_color="#2b2b2b", corner_radius=0)
    vuln_content.pack(fill="both", expand=True, padx=20, pady=10)
    
    os_vulns = len(scan_results.get("OS Vulnerabilities", []))
    
    if not os_vulns:
        status_label = ctk.CTkLabel(
            vuln_content,
            text="🟢 100% SECURE",
            font=("Arial", 24, "bold"),
            text_color="#4CAF50"
        )
        status_label.pack(pady=20)
    else:
        os_label = ctk.CTkLabel(
            vuln_content,
            text=f"🔴 Operating System Vulnerabilities: {os_vulns}",
            font=("Arial", 16, "bold"),
            text_color="#F44336",
            anchor="w"
        )
        os_label.pack(pady=10, fill="x")
        
        for cve_id, desc in scan_results.get("OS Vulnerabilities", []):
            vuln_label = ctk.CTkLabel(
                vuln_content,
                text=f"• {cve_id}: {desc}",
                font=("Arial", 12),
                text_color="white",
                anchor="w",
                wraplength=400
            )
            vuln_label.pack(pady=2, fill="x")
    
    # Create recommendations section
    rec_frame = ctk.CTkFrame(top_container, fg_color="#2b2b2b", corner_radius=0)
    rec_frame.pack(side="left", fill="both", expand=True, padx=1)
    
    # Recommendations header
    rec_header = ctk.CTkFrame(rec_frame, fg_color="#1e1e1e", corner_radius=0, height=40)
    rec_header.pack(fill="x", pady=0)
    rec_header.pack_propagate(False)
    
    rec_title = ctk.CTkLabel(
        rec_header,
        text="💡 Security Recommendations",
        font=("Arial", 20, "bold"),
        text_color="#64B5F6"
    )
    rec_title.pack(pady=5)
    
    # Generate recommendations
    recommendations = []
    if os_vulns > 0:
        recommendations.append(("🔴 Critical", "Update your operating system to patch known vulnerabilities"))
    if len(scan_results.get("Processes", [])) > 100:
        recommendations.append(("🟡 Important", "Review running processes and terminate unnecessary ones"))
    if len(scan_results.get("Connections", [])) > 50:
        recommendations.append(("🟡 Important", "Monitor network connections for suspicious activity"))
    
    if not recommendations:
        recommendations.append(("🟢 Good", "Your system appears to be well-secured! Continue monitoring regularly."))
    
    # Display recommendations
    rec_container = ctk.CTkFrame(rec_frame, fg_color="#2b2b2b", corner_radius=0)
    rec_container.pack(fill="both", expand=True, padx=20, pady=10)
    
    for priority, rec in recommendations:
        rec_label = ctk.CTkLabel(
            rec_container,
            text=f"{priority}: {rec}",
            font=("Arial", 14),
            text_color="white",
            anchor="w",
            justify="left"
        )
        rec_label.pack(pady=5, anchor="w")
    
    # Create bottom half container for detailed sections
    bottom_container = ctk.CTkFrame(results_frame, fg_color="#1a1a1a", corner_radius=0)
    bottom_container.pack(fill="both", expand=True, pady=(5, 0))
    
    # Calculate section widths
    screen_width = root.winfo_screenwidth()
    section_width = int(screen_width * 0.198)
    
    # Port Scan Section
    port_content = create_scrollable_section(bottom_container, "Port Scan", "🔌", section_width)
    
    if not open_ports:
        port_status = ctk.CTkLabel(
            port_content,
            text="🟢 No open ports detected",
            font=("Arial", 14),
            text_color="#4CAF50",
            anchor="w",
            wraplength=section_width - 50,
            fg_color="#2b2b2b"
        )
        port_status.pack(pady=5, fill="x")
    else:
        port_status = ctk.CTkLabel(
            port_content,
            text=f"🔴 {open_ports} open ports detected",
            font=("Arial", 14),
            text_color="#F44336",
            anchor="w",
            wraplength=section_width - 50,
            fg_color="#2b2b2b"
        )
        port_status.pack(pady=5, fill="x")
        for port in scan_results.get("Open Ports", []):
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "Unknown"
            port_text = f"• Port {port} ({service})"
            port_label = ctk.CTkLabel(
                port_content,
                text=port_text,
                font=("Arial", 12),
                text_color="white",
                anchor="w",
                wraplength=section_width - 50,
                fg_color="#2b2b2b"
            )
            port_label.pack(pady=2, fill="x")
    
    # Running Processes Section
    proc_content = create_scrollable_section(bottom_container, "Running Processes", "⚙️", section_width)
    
    total_procs = len(scan_results.get("Processes", []))
    proc_count = ctk.CTkLabel(
        proc_content,
        text=f"Total Processes: {total_procs}",
        font=("Arial", 14),
        text_color="#64B5F6",
        anchor="w",
        wraplength=section_width - 50,
        fg_color="#2b2b2b"
    )
    proc_count.pack(pady=5, fill="x")
    
    for proc in scan_results.get("Processes", []):
        proc_label = ctk.CTkLabel(
            proc_content,
            text=f"• {proc}",
            font=("Arial", 12),
            text_color="white",
            anchor="w",
            wraplength=section_width - 50,
            fg_color="#2b2b2b"
        )
        proc_label.pack(pady=2, fill="x")
    
    # Network Connections Section
    conn_content = create_scrollable_section(bottom_container, "Network Connections", "🌐", section_width)
    
    connections = scan_results.get("Connections", [])
    total_conns = len(connections)
    conn_count = ctk.CTkLabel(
        conn_content,
        text=f"Total Connections: {total_conns}",
        font=("Arial", 14),
        text_color="#64B5F6",
        anchor="w",
        wraplength=section_width - 50,
        fg_color="#2b2b2b"
    )
    conn_count.pack(pady=5, fill="x")
    
    for conn in connections:
        conn_label = ctk.CTkLabel(
            conn_content,
            text=f"• {conn}",
            font=("Arial", 12),
            text_color="white",
            anchor="w",
            wraplength=section_width - 50,
            fg_color="#2b2b2b"
        )
        conn_label.pack(pady=2, fill="x")
    
    # System Information Section
    sys_content = create_scrollable_section(bottom_container, "System Info", "💻", section_width)
    
    sys_info = scan_results.get("System Info", "")
    sys_label = ctk.CTkLabel(
        sys_content,
        text=sys_info,
        font=("Arial", 12),
        text_color="white",
        anchor="w",
        justify="left",
        wraplength=section_width - 50,
        fg_color="#2b2b2b"
    )
    sys_label.pack(pady=5, fill="x")
    
    # Buttons Section (replacing vulnerabilities section)
    button_content = create_scrollable_section(bottom_container, "Actions", "🔧", section_width)
    
    # View Report Button
    view_report_button = ctk.CTkButton(
        button_content, 
        text="📋 OPEN REPORT", 
        font=("Arial", 14, "bold"),
        height=40,
        corner_radius=8,
        command=open_scan_report
    )
    view_report_button.pack(pady=(20, 10), padx=20, fill="x")

    # Back to Home Button
    back_button = ctk.CTkButton(
        button_content, 
        text="🏠 BACK TO HOME", 
        font=("Arial", 14, "bold"),
        height=40,
        corner_radius=8,
        command=lambda: show_page(home_frame)
    )
    back_button.pack(pady=(10, 20), padx=20, fill="x")
    
    # Add a note about detailed report at the bottom
    note_frame = ctk.CTkFrame(results_frame, fg_color="transparent")
    note_frame.pack(side="bottom", fill="x", pady=5)
    
    note_label = ctk.CTkLabel(
        note_frame,
        text="📝 Detailed technical report has been saved to file",
        font=("Arial", 12),
        text_color="gray70"
    )
    note_label.pack(pady=5)

def create_network_connections_section(parent, connections):
    """Create a section for network connections"""
    conn_frame = create_visual_section(parent, "Network Connections", "", "🌐")
    
    # Count connections
    total_conns = len(connections)
    conn_count = ctk.CTkLabel(
        conn_frame,
        text=f"Total Active Connections: {total_conns}",
        font=("Arial", 14),
        text_color="#64B5F6"
    )
    conn_count.pack(pady=5, anchor="w")
    
    # List connections
    for conn in connections[:20]:  # Show first 20 connections
        conn_label = ctk.CTkLabel(
            conn_frame,
            text=f"• {conn}",
            font=("Arial", 12),
            text_color="white",
            anchor="w"
        )
        conn_label.pack(pady=2, padx=20, anchor="w")
    
    if total_conns > 20:
        more_label = ctk.CTkLabel(
            conn_frame,
            text=f"... and {total_conns - 20} more connections",
            font=("Arial", 12),
            text_color="gray70",
            anchor="w"
        )
        more_label.pack(pady=2, padx=20, anchor="w")

def create_system_info_section(parent, system_info):
    """Create a section for system information"""
    sys_frame = create_visual_section(parent, "System Information", "", "💻")
    
    # Display system info
    sys_label = ctk.CTkLabel(
        sys_frame,
        text=system_info,
        font=("Arial", 12),
        text_color="white",
        anchor="w",
        justify="left"
    )
    sys_label.pack(pady=5, padx=20, anchor="w")

# Buttons for results page
results_button_frame = ctk.CTkFrame(results_frame, fg_color="transparent")
results_button_frame.pack(pady=15)

def open_scan_report():
    """Open the scan report file with the default application."""
    try:
        if platform.system() == 'Windows':
            os.startfile(output_file)
        elif platform.system() == 'Darwin':  # macOS
            subprocess.call(('open', output_file))
        else:  # Linux
            subprocess.call(('xdg-open', output_file))
    except Exception as e:
        messagebox.showerror("Error", f"Could not open report file: {e}")

view_report_button = ctk.CTkButton(
    results_button_frame, 
    text="📋 OPEN REPORT", 
    font=("Arial", 14, "bold"),
    width=180,
    height=40,
    corner_radius=8,
    command=open_scan_report
)
view_report_button.pack(side="left", padx=10)

back_button = ctk.CTkButton(
    results_button_frame, 
    text="🏠 BACK TO HOME", 
    font=("Arial", 14, "bold"),
    width=180,
    height=40,
    corner_radius=8,
    command=lambda: show_page(home_frame)
)
back_button.pack(side="left", padx=10)

# Version information at the bottom
version_label = ctk.CTkLabel(
    root,
    text="v1.0.0",
    font=("Arial", 10),
    text_color=("gray60" if ctk.get_appearance_mode() == "light" else "gray70")
)
version_label.place(relx=0.95, rely=0.98, anchor="se")

# ---- Start App ----
# Show the welcome screen first
show_page(welcome_frame)
root.mainloop() 