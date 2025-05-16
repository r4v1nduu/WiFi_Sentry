import tkinter as tk
import customtkinter as ctk # type: ignore
from tkinter import messagebox

# Import GUI components
from gui.dashboard import DashboardTab
from gui.details import DetailsTab
from gui.about import AboutTab
from gui.scanner import ScanManager


class WiFiSentry(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("W!F! Sentry")
        # self.iconbitmap("/assets/icon.ico")
        self.geometry("420x640")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # scan manager
        self.scan_manager = ScanManager()
        
        # UI elements
        self.create_ui()
        
    def create_ui(self):
        # main frame
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.header_label = ctk.CTkLabel(
            self.main_frame, 
            text="WiFi Sentry", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.header_label.pack(pady=10,)
        
        # Description
        self.desc_label = ctk.CTkLabel(
            self.main_frame,
            text="analyze public WiFi network before you use it",
            font=ctk.CTkFont(size=12)
        )
        self.desc_label.pack(pady=(0,2))
        
        # Tabs
        self.tab_view = ctk.CTkTabview(self.main_frame)
        self.tab_view.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.dashboard_tab = self.tab_view.add("Dashboard")
        self.details_tab = self.tab_view.add("Details")
        self.about_tab = self.tab_view.add("About")
        
        self.dashboard = DashboardTab(self.dashboard_tab, self.scan_manager)
        self.details = DetailsTab(self.details_tab)
        self.about = AboutTab(self.about_tab)
        
        # Connect scanner with components
        self.scan_manager.set_ui_components(
            self.dashboard,
            self.details
        )
    
    def on_closing(self):

        if self.scan_manager.is_scanning():
            if messagebox.askokcancel("Quit", "A scan is in progress. Do you want to quit anyway?"):
                self.destroy()
        else:
            self.destroy()