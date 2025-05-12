import tkinter as tk
from tkinter import ttk, scrolledtext
import customtkinter as ctk # type: ignore
from typing import Dict, Any


class DetailsTab:
    def __init__(self, parent):
        self.parent = parent
        
        # Text widgets for different analysis types
        self.text_widgets = {}
        
        # Initialize UI
        self.setup_ui()
    
    def setup_ui(self):
        # Create notebook for different analysis results
        self.details_notebook = ttk.Notebook(self.parent)
        self.details_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab names and their respective frames
        tabs = [
            ("Network", "network"), 
            ("ARP", "arp"), 
            ("DNS", "dns"), 
            ("BSSID", "bssid"), 
            ("SSID", "ssid")
        ]
        
        # Create tabs and text widgets
        for tab_name, tab_id in tabs:
            # Create frame
            frame = ctk.CTkFrame(self.details_notebook)
            
            # Create scrolled text area
            text_widget = scrolledtext.ScrolledText(frame)
            text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            text_widget.config(state=tk.DISABLED)
            
            # Add frame to notebook
            self.details_notebook.add(frame, text=tab_name)
            
            # Store the text widget for later reference
            self.text_widgets[tab_id] = text_widget
    
    def update_text(self, tab_id, text):
        """Update the content of a text widget"""
        if tab_id in self.text_widgets:
            text_widget = self.text_widgets[tab_id]
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.insert(tk.END, text)
            text_widget.config(state=tk.DISABLED)
    
    def clear_all_tabs(self):
        """Clear all text widgets"""
        for text_widget in self.text_widgets.values():
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            text_widget.config(state=tk.DISABLED)