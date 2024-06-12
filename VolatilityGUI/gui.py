import tkinter as tk
from tkinter import filedialog, simpledialog, ttk
from file_operations import select_file, export_to_csv
from volatility_operations import start_analysis, go_back, check_connection

def setup_gui(root):
    root.file_path = None  # Initialize file_path attribute

    global result_frame, result_text, export_button, scan_combobox, main_frame, plugin_mapping

    root.title("Memory Dump Analyzer")
    
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    window_width = int(screen_width * 0.8)
    window_height = int(screen_height * 0.8)
    root.geometry(f"{window_width}x{window_height}")
    root.resizable(False, False)

    main_frame = tk.Frame(root, bg="#1c1c1c")
    main_frame.pack(fill="both", expand=True)

    instruction_label = tk.Label(main_frame, text="Click the button to import data", font=("Helvetica", 16, "bold"), bg="#1c1c1c", fg="orange")
    instruction_label.pack(pady=20)

    canvas = tk.Canvas(main_frame, width=window_width, height=window_height, bg="#1c1c1c", highlightthickness=0)
    canvas.pack(fill="both", expand=True)

    create_oval_button(canvas, window_width, window_height)

    result_frame = tk.Frame(root, bg="#1c1c1c")

    button_frame = tk.Frame(result_frame, bg="#1c1c1c")
    button_frame.pack(pady=20)

    back_button = tk.Button(button_frame, text="Back", command=lambda: go_back(main_frame, result_frame), font=("Helvetica", 12), bg="orange", fg="black", width=10)
    back_button.pack(side=tk.LEFT, padx=10)

    add_plugin_button = tk.Button(button_frame, text="Add Plugin", command=lambda: add_plugin(scan_combobox, plugin_mapping), font=("Helvetica", 12), bg="orange", fg="black", width=15)
    add_plugin_button.pack(side=tk.RIGHT, padx=10)

    plugin_mapping = {
        "PsList": "volatility3.plugins.windows.pslist.PsList",
        "DllList": "volatility3.plugins.windows.dlllist.DllList",
        "Handles": "volatility3.plugins.windows.handles.Handles",
        "CmdLine": "volatility3.plugins.windows.cmdline.CmdLine",
        "NetScan": "volatility3.plugins.windows.netscan.NetScan",
        "HiveList": "volatility3.plugins.windows.registry.hivelist.HiveList",
        "PrintKey": "volatility3.plugins.windows.registry.printkey.PrintKey",
        "Malfind": "volatility3.plugins.windows.malfind.Malfind",
        "SvcScan": "volatility3.plugins.windows.svcscan.SvcScan",
        "Threads": "volatility3.plugins.windows.threads.Threads",
        "FileScan": "volatility3.plugins.windows.filescan.FileScan",
        "ModScan": "volatility3.plugins.windows.modscan.ModScan",
        "DriverIRP": "volatility3.plugins.windows.driverirp.DriverIRP",
        "VerInfo": "volatility3.plugins.windows.verinfo.VerInfo",
        "GetServiceSIDs": "volatility3.plugins.windows.getservicesids.GetServiceSIDs",
        "GetSIDs": "volatility3.plugins.windows.getsids.GetSIDs",
        "Privileges": "volatility3.plugins.windows.privileges.Privileges"
    }

    scan_combobox = ttk.Combobox(result_frame, values=list(plugin_mapping.keys()), font=("Helvetica", 12))
    scan_combobox.set("Choose scan")
    scan_combobox.pack(pady=10)

    start_button = tk.Button(result_frame, text="Start", command=lambda: start_analysis(scan_combobox, result_text, export_button, root.file_path, update_result_text, plugin_mapping), font=("Helvetica", 12), bg="orange", fg="black", width=10)
    start_button.pack(pady=10)

    result_text_frame = tk.Frame(result_frame)
    result_text_frame.pack(fill="both", expand=True, pady=10, padx=20)

    result_text_scrollbar = tk.Scrollbar(result_text_frame)
    result_text_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    result_text = tk.Text(result_text_frame, wrap="word", width=100, height=20, font=("Helvetica", 14), bg="white", fg="black", yscrollcommand=result_text_scrollbar.set)
    result_text.pack(fill="both", expand=True)
    result_text.config(state=tk.DISABLED)  # Set the result_text to read-only

    result_text_scrollbar.config(command=result_text.yview)

    # Create a frame for the export and clear buttons and centralize them
    export_clear_frame = tk.Frame(result_frame, bg="#1c1c1c")
    export_clear_frame.pack(pady=10)

    # Add the clear button to the frame
    clear_button = tk.Button(export_clear_frame, text="Clear", command=lambda: clear_result_text(result_text), font=("Helvetica", 12), bg="orange", fg="black", width=15)
    clear_button.pack(side=tk.LEFT, padx=10, pady=10)

    # Add the export button to the frame, initially disabled
    export_button = tk.Button(export_clear_frame, text="Export Results", command=lambda: export_to_csv(result_text), font=("Helvetica", 12), bg="orange", fg="black", width=15)
    export_button.pack(side=tk.RIGHT, padx=10, pady=10)
    export_button.config(state=tk.DISABLED)  # Initially disable the button

    canvas.bind("<Button-1>", lambda event: on_click(event, canvas, window_width, window_height, main_frame, result_frame, result_text, root))

def create_oval_button(canvas, window_width, window_height):
    canvas.delete("all")
    oval_radius = min(window_width, window_height) // 10
    x0 = (window_width // 2) - oval_radius
    y0 = (window_height // 2) - oval_radius
    x1 = (window_width // 2) + oval_radius
    y1 = (window_height // 2) + oval_radius
    canvas.create_oval(x0, y0, x1, y1, fill="orange", outline="")
    canvas.create_oval(x0-2, y0-2, x1+2, y1+2, outline="#ff7f00")
    canvas.create_oval(x0+2, y0+2, x1-2, y1-2, outline="#ffc966")
    canvas.create_text((window_width // 2, window_height // 2), text="Import Data", fill="black", font=("Helvetica", 14, "bold"))

def on_click(event, canvas, window_width, window_height, main_frame, result_frame, result_text, root):
    x, y = event.x, event.y
    oval_radius = min(window_width, window_height) // 10
    x0 = (window_width // 2) - oval_radius
    y0 = (window_height // 2) - oval_radius
    x1 = (window_width // 2) + oval_radius
    y1 = (window_height // 2) + oval_radius
    if (x0 < x < x1) and (y0 < y < y1):
        root.file_path = select_file(main_frame, result_frame, result_text)

def clear_result_text(result_text):
    result_text.config(state=tk.NORMAL)  # Enable writing
    result_text.delete(1.0, tk.END)  # Clear all text
    result_text.config(state=tk.DISABLED)  # Disable writing again

def update_result_text(result_text, message):
    result_text.config(state=tk.NORMAL)  # Enable writing
    result_text.insert(tk.END, message + "\n")
    result_text.config(state=tk.DISABLED)  # Disable writing again

def add_plugin(scan_combobox, plugin_mapping):
    # Ask the user for the short name and full path of the new plugin
    short_name = simpledialog.askstring("Input", "Enter short name for the plugin:", parent=scan_combobox)
    if not short_name:
        return

    full_path = simpledialog.askstring("Input", "Enter full path for the plugin:", parent=scan_combobox)
    if not full_path:
        return

    # Add the new plugin to the plugin mapping and update the combobox
    plugin_mapping[short_name] = full_path
    scan_combobox['values'] = list(plugin_mapping.keys())
