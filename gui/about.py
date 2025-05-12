import tkinter as tk
import customtkinter as ctk # type: ignore


class AboutTab:
    def __init__(self, parent):
        self.parent = parent
        
        # Initialize UI
        self.setup_ui()
    
    def setup_ui(self):
        about_frame = ctk.CTkFrame(self.parent)
        about_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # App title
        app_title = ctk.CTkLabel(
            about_frame,
            text="WiFi Sentry : V:1.0.0",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        app_title.pack(padx=8)
        
        # Description
        desc_text = """
        WiFiSentry is a comprehensive WiFi security analysis tool designed to help 
        identify potential security risks in your wireless network.
        
        The tool performs five key types of analysis:
        - Network security configuration scan
        - ARP poisoning detection
        - DNS security analysis
        - BSSID analysis for rogue access points
        - SSID analysis for suspicious networks
        
        This application is intended for educational and security audit purposes only.
        """
        
        desc_label = ctk.CTkLabel(
            about_frame,
            text=desc_text,
            font=ctk.CTkFont(size=12),
            justify=tk.CENTER,
            wraplength=300
        )
        desc_label.pack(pady=20)