import tkinter as tk
import customtkinter as ctk # type: ignore


class DashboardTab:
    def __init__(self, parent, scan_manager):
        self.parent = parent
        self.scan_manager = scan_manager
        
        self.status_label = None
        self.scan_button = None
        self.progress_bar = None
        self.progress_text = None
        self.risk_indicators = {}
        
        # UI
        self.setup_ui()
    
    def setup_ui(self):
        # Main container frame
        self.main_frame = ctk.CTkFrame(self.parent)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Status and controls
        self.controls_frame = ctk.CTkFrame(self.main_frame)
        self.controls_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Status label
        self.status_label = ctk.CTkLabel(
            self.controls_frame,
            text="Ready to Scan",
            font=ctk.CTkFont(size=14)
        )
        self.status_label.pack(pady=10)
        
        # Scan button and progress bar
        self.scan_button = ctk.CTkButton(
            self.controls_frame, 
            text="Start Scan", 
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self.scan_manager.start_scan,
            width=160,
            height=40
        )
        self.scan_button.pack(pady=(0, 10))
        
        self.progress_frame = ctk.CTkFrame(self.controls_frame)
        self.progress_frame.pack(fill=tk.X, pady=5, padx=5)
        
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)
        self.progress_bar.set(0)
        
        self.progress_text = ctk.CTkLabel(
            self.progress_frame,
            text="0%"
        )
        self.progress_text.pack(pady=5)
        
        # Risk summary
        self.risk_frame = ctk.CTkFrame(self.main_frame)
        self.risk_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.risk_title = ctk.CTkLabel(
            self.risk_frame,
            text="Risk Summary",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.risk_title.pack(pady=10)
        
        # Risk indicators
        risk_areas = [
            "Network Security", "ARP Security", "DNS Security", 
            "BSSID Security", "SSID Security"
        ]
        
        for area in risk_areas:
            row_frame = ctk.CTkFrame(self.risk_frame)
            row_frame.pack(fill=tk.X, padx=5, pady=5)
            
            label = ctk.CTkLabel(
                row_frame,
                text=area,
                width=150,
                anchor="w"
            )
            label.pack(side=tk.LEFT, padx=5)

            status = ctk.CTkLabel(
                row_frame,
                text="Unknown",
                width=100
            )
            status.pack(side=tk.LEFT, padx=5)
            
            indicator_frame = ctk.CTkFrame(row_frame, width=20, height=20)
            indicator_frame.pack(side=tk.LEFT, padx=5)
            
            indicator_canvas = tk.Canvas(indicator_frame, width=20, height=20, 
                                      bg="#2b2b2b", highlightthickness=0)
            indicator_canvas.pack()
            
            circle = indicator_canvas.create_oval(2, 2, 18, 18, fill="#808080")
            
            self.risk_indicators[area] = {
                "status_label": status,
                "indicator": indicator_canvas,
                "circle": circle
            }
    
    def update_status(self, text):

        self.status_label.configure(text=text)
    
    def update_progress(self, value, percent):
        
        self.progress_bar.set(value)
        self.progress_text.configure(text=f"{percent}%")
    
    def update_risk_indicator(self, area, risk_level):
        
        if area not in self.risk_indicators:
            return
        
        # colors based on risk level
        risk_colors = {
            "SAFE": "#4CAF50",  # Green
            "LOW": "#4CAF50",   # Green
            "Low": "#4CAF50",   # Green
            "low": "#4CAF50",   # Green
            "none": "#4CAF50",  # Green
            "NONE": "#4CAF50",  # Green
            "medium": "#FFEB3B", # Yellow
            "MEDIUM": "#FFEB3B", # Yellow
            "Medium": "#FFEB3B", # Yellow
            "high": "#F44336",  # Red
            "HIGH": "#F44336",  # Red
            "High": "#F44336",  # Red
            "CRITICAL": "#F44336", # Red
            "critical": "#F44336", # Red
            "Critical": "#F44336"  # Red
        }
        
        indicator_color = risk_colors.get(risk_level, "#808080")
        
        self.risk_indicators[area]["status_label"].configure(text=risk_level)
        self.risk_indicators[area]["indicator"].itemconfig(
            self.risk_indicators[area]["circle"], 
            fill=indicator_color
        )
    
    def enable_scan_button(self, enable=True):
        
        self.scan_button.configure(state="normal" if enable else "disabled")