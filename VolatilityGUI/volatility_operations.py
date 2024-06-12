import os
import importlib
import tkinter as tk  # Import tkinter module
from tkinter import END
from volatility3.framework import contexts, automagic, exceptions
from volatility3.plugins.windows import pslist

results = []

def check_connection(file_path, result_text, update_result_text):
    global results
    try:
        update_result_text(result_text, "Starting connection check...")
        
        # Create a new context
        context = contexts.Context()
        single_location = f"file:{file_path}"
        context.config['automagic.LayerStacker.single_location'] = single_location

        # Initialize and configure the plugin
        update_result_text(result_text, f"Configuring plugin for file: {file_path}")
        plugin = pslist.PsList(context, config_path='plugins.windows.pslist')
        plugin.config['single_location'] = single_location

        # Run automagic modules to set up the layers and address spaces
        update_result_text(result_text, "Running automagic modules...")
        automagics = automagic.available(context)
        automagic_modules = automagic.choose_automagic(automagics, plugin)
        automagic.run(automagic_modules, context, plugin, 'plugins.windows.pslist')

        # Validate the plugin configuration
        unsatisfied = plugin.unsatisfied(context, 'plugins.windows.pslist')
        if unsatisfied:
            update_result_text(result_text, "Unsatisfied requirements for connection check:")
            for requirement in unsatisfied:
                update_result_text(result_text, f"Unsatisfied: {requirement}")
            return
        
        # Run the plugin
        update_result_text(result_text, "Running the plugin...")
        results = plugin.run()
        if results:
            update_result_text(result_text, "Connection to the memory dump file established successfully.")
        else:
            update_result_text(result_text, "No results from the connection check. The file may be invalid or unreadable.")

    except exceptions.PluginRequirementException as e:
        update_result_text(result_text, f"Plugin requirement error: {str(e)}")
    except exceptions.VolatilityException as e:
        update_result_text(result_text, f"Volatility framework error: {str(e)}")
    except Exception as e:
        update_result_text(result_text, f"Unexpected error during connection check: {str(e)}")

def start_analysis(scan_combobox, result_text, export_button, file_path, update_result_text, plugin_mapping):
    global results
    selected_scan = scan_combobox.get()
    update_result_text(result_text, f"Selected scan: {selected_scan}")

    try:
        # Get the full plugin path from the mapping
        full_plugin_path = plugin_mapping[selected_scan]
        update_result_text(result_text, f"Using plugin: {full_plugin_path}")

        # Create a new context
        context = contexts.Context()
        single_location = f"file:{file_path}"
        context.config['automagic.LayerStacker.single_location'] = single_location
        update_result_text(result_text, "Context and file location configured.")

        # Dynamically load the plugin
        plugin_module, plugin_class_name = full_plugin_path.rsplit('.', 1)
        plugin_module = importlib.import_module(plugin_module)
        plugin_class = getattr(plugin_module, plugin_class_name)

        # Initialize and configure the plugin
        update_result_text(result_text, f"Loading plugin: {full_plugin_path}")
        plugin = plugin_class(context, config_path=full_plugin_path)
        plugin.config['single_location'] = single_location

        # Run automagic modules to set up the layers and address spaces
        update_result_text(result_text, "Running automagic modules...")
        automagics = automagic.available(context)
        automagic_modules = automagic.choose_automagic(automagics, plugin)
        errors = automagic.run(automagic_modules, context, plugin, full_plugin_path)
        if errors:
            update_result_text(result_text, f"Automagic errors: {errors}")
            return

        # Validate the plugin configuration
        unsatisfied = plugin.unsatisfied(context, full_plugin_path)
        if unsatisfied:
            update_result_text(result_text, f"Unsatisfied requirements: {unsatisfied}")
            for requirement in unsatisfied:
                update_result_text(result_text, f"Unsatisfied: {requirement}")
            return

        # Run the plugin
        update_result_text(result_text, "Processing...")
        results = plugin.run()
        update_result_text(result_text, "Scan complete.")
        for result in results:
            update_result_text(result_text, str(result))

        # Enable the export button
        export_button.config(state=tk.NORMAL)

    except exceptions.PluginRequirementException as e:
        update_result_text(result_text, f"Plugin requirement error: {str(e)}")
    except exceptions.VolatilityException as e:
        update_result_text(result_text, f"Volatility framework error: {str(e)}")
    except Exception as e:
        update_result_text(result_text, f"Unexpected error during processing: {str(e)}")

def go_back(main_frame, result_frame):
    result_frame.pack_forget()
    main_frame.pack(fill="both", expand=True)
