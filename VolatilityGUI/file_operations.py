import csv
from tkinter import filedialog, END
from volatility_operations import check_connection

results = []

def select_file(main_frame, result_frame, result_text):
    file_path = filedialog.askopenfilename(title="Select a memory dump file", filetypes=[
        ("Memory dump files", "*.dmp *.vmem *.raw *.mem")
    ])
    if file_path:
        from gui import update_result_text
        update_result_text(result_text, f"Selected file: {file_path}")
        main_frame.pack_forget()
        result_frame.pack(fill="both", expand=True)
        check_connection(file_path, result_text, update_result_text)
    else:
        from gui import update_result_text
        update_result_text(result_text, "No file selected.")
    return file_path

def export_to_csv(result_text):
    global results
    try:
        export_file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not export_file_path:
            return
        
        with open(export_file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(results[0].keys())
            for result in results:
                writer.writerow(result.values())
        
        from gui import update_result_text
        update_result_text(result_text, f"Results exported successfully to {export_file_path}")
    except Exception as e:
        from gui import update_result_text
        update_result_text(result_text, f"Error exporting results: {str(e)}")
