import tkinter as tk
from tkinter import ttk, scrolledtext
import customtkinter as ctk # type: ignore


class DetailsTab:
    def __init__(self, parent):
        self.parent = parent
        
        self.text_widgets = {}
        
        # UI
        self.setup_ui()
    
    def setup_ui(self):
        
        self.details_notebook = ttk.Notebook(self.parent)
        self.details_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tabs = [
            ("Network", "network"), 
            ("ARP", "arp"), 
            ("DNS", "dns"), 
            ("BSSID", "bssid"), 
            ("SSID", "ssid")
        ]
        
        for tab_name, tab_id in tabs:
            
            frame = ctk.CTkFrame(self.details_notebook)
            
            
            text_widget = scrolledtext.ScrolledText(frame)
            text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            text_widget.config(state=tk.DISABLED)
            
            self.details_notebook.add(frame, text=tab_name)
            
            self.text_widgets[tab_id] = text_widget
    
    def update_text(self, tab_id, text):
        
        if tab_id in self.text_widgets:
            text_widget = self.text_widgets[tab_id]
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.insert(tk.END, text)
            text_widget.config(state=tk.DISABLED)
    
    def clear_all_tabs(self):
        
        for text_widget in self.text_widgets.values():
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.config(state=tk.DISABLED)