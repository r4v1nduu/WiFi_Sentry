import customtkinter as ctk # type: ignore
import tkinter as tk

from gui.app import WiFiSentry

ctk.set_appearance_mode("Dark")  # Mode
ctk.set_default_color_theme("dark-blue")  # Theme

if __name__ == "__main__":
    app = WiFiSentry()
    app.mainloop()