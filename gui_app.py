import customtkinter as ctk
import threading
import time
from client_controller import ClientController

# Configuration
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# Enhanced Color Palette
COLORS = {
    "bg_main": "#121212",        # Very dark grey, almost black
    "bg_sidebar": "#1E1E1E",     # Slightly lighter for sidebar
    "bg_card": "#252525",        # Card background
    "accent": "#BB86FC",         # Purple accent (Material Dark)
    "accent_hover": "#9965f4",   # Lighter purple for hover
    "text": "#E0E0E0",           # High emphasis text
    "text_secondary": "#A0A0A0", # Medium emphasis text
    "bubble_me": "#3700B3",      # Darker purple for my messages
    "bubble_other": "#2C2C2C",   # Dark grey for other messages
    "error": "#CF6679",          # Soft red
    "success": "#03DAC6",        # Teal
    "border": "#333333"          # Subtle borders
}

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Secure Messenger")
        self.geometry("1100x750")
        self.minsize(900, 650)

        self.controller = ClientController()
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.current_frame = None
        self.show_login()

    def show_frame(self, frame_class, **kwargs):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = frame_class(self, **kwargs)
        self.current_frame.grid(row=0, column=0, sticky="nsew")

    def show_login(self):
        self.show_frame(LoginFrame)

    def show_register(self):
        self.show_frame(RegisterFrame)

    def show_main(self):
        self.show_frame(MainFrame)

class BaseAuthFrame(ctk.CTkFrame):
    """Base class for Login and Register frames to share styling"""
    def __init__(self, master):
        super().__init__(master, fg_color=COLORS["bg_main"])
        self.master = master
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.card = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=20, width=400, border_width=1, border_color=COLORS["border"])
        self.card.grid(row=0, column=0, padx=20, pady=20)
        self.card.grid_columnconfigure(0, weight=1)

    def create_entry(self, placeholder, show=None):
        return ctk.CTkEntry(
            self.card,
            placeholder_text=placeholder,
            show=show,
            width=320,
            height=45,
            corner_radius=10,
            border_width=1,
            border_color=COLORS["border"],
            fg_color=COLORS["bg_main"],
            text_color=COLORS["text"],
            placeholder_text_color=COLORS["text_secondary"]
        )

    def create_button(self, text, command, is_primary=True):
        fg = COLORS["accent"] if is_primary else "transparent"
        hover = COLORS["accent_hover"] if is_primary else COLORS["bg_sidebar"]
        text_col = COLORS["bg_main"] if is_primary else COLORS["text_secondary"]
        border = 0 if is_primary else 1
        
        return ctk.CTkButton(
            self.card,
            text=text,
            command=command,
            width=320,
            height=45,
            corner_radius=10,
            fg_color=fg,
            hover_color=hover,
            text_color=text_col,
            border_width=border,
            border_color=COLORS["text_secondary"],
            font=ctk.CTkFont(size=15, weight="bold" if is_primary else "normal")
        )

class LoginFrame(BaseAuthFrame):
    def __init__(self, master):
        super().__init__(master)
        
        # Title
        ctk.CTkLabel(
            self.card, 
            text="Welcome Back", 
            font=ctk.CTkFont(family="Segoe UI", size=32, weight="bold"),
            text_color=COLORS["text"]
        ).grid(row=0, column=0, padx=40, pady=(50, 10))

        ctk.CTkLabel(
            self.card, 
            text="Sign in to your secure account", 
            font=ctk.CTkFont(family="Segoe UI", size=14),
            text_color=COLORS["text_secondary"]
        ).grid(row=1, column=0, padx=40, pady=(0, 40))

        # Inputs
        self.username_entry = self.create_entry("Username")
        self.username_entry.grid(row=2, column=0, padx=40, pady=10)

        self.password_entry = self.create_entry("Password", show="*")
        self.password_entry.grid(row=3, column=0, padx=40, pady=10)

        # Buttons
        self.login_button = self.create_button("Login", self.login, is_primary=True)
        self.login_button.grid(row=4, column=0, padx=40, pady=(30, 15))

        self.register_button = self.create_button("Create Account", self.go_to_register, is_primary=False)
        self.register_button.grid(row=5, column=0, padx=40, pady=(0, 50))
        
        self.status_label = ctk.CTkLabel(self.card, text="", text_color=COLORS["error"])
        self.status_label.grid(row=6, column=0, padx=40, pady=(0, 20))

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            self.status_label.configure(text="Please enter username and password", text_color=COLORS["error"])
            return
        
        self.status_label.configure(text="Logging in...", text_color=COLORS["accent"])
        self.update()
        
        success, msg = self.master.controller.login(username, password)
        if success:
            self.master.show_main()
        else:
            self.status_label.configure(text=msg, text_color=COLORS["error"])

    def go_to_register(self):
        self.master.show_register()

class RegisterFrame(BaseAuthFrame):
    def __init__(self, master):
        super().__init__(master)
        
        # Title
        ctk.CTkLabel(
            self.card, 
            text="Create Account", 
            font=ctk.CTkFont(family="Segoe UI", size=32, weight="bold"),
            text_color=COLORS["text"]
        ).grid(row=0, column=0, padx=40, pady=(50, 10))

        ctk.CTkLabel(
            self.card, 
            text="Join the secure network", 
            font=ctk.CTkFont(family="Segoe UI", size=14),
            text_color=COLORS["text_secondary"]
        ).grid(row=1, column=0, padx=40, pady=(0, 40))

        # Inputs
        self.username_entry = self.create_entry("Username")
        self.username_entry.grid(row=2, column=0, padx=40, pady=10)

        self.password_entry = self.create_entry("Password", show="*")
        self.password_entry.grid(row=3, column=0, padx=40, pady=10)

        self.confirm_entry = self.create_entry("Confirm Password", show="*")
        self.confirm_entry.grid(row=4, column=0, padx=40, pady=10)

        # Buttons
        self.register_button = self.create_button("Sign Up", self.register, is_primary=True)
        self.register_button.grid(row=5, column=0, padx=40, pady=(30, 15))

        self.login_button = self.create_button("Back to Login", self.go_to_login, is_primary=False)
        self.login_button.grid(row=6, column=0, padx=40, pady=(0, 50))
        
        self.status_label = ctk.CTkLabel(self.card, text="", text_color=COLORS["error"])
        self.status_label.grid(row=7, column=0, padx=40, pady=(0, 20))

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()

        if not username or not password:
            self.status_label.configure(text="All fields are required", text_color=COLORS["error"])
            return
        
        if password != confirm:
            self.status_label.configure(text="Passwords do not match", text_color=COLORS["error"])
            return

        self.status_label.configure(text="Creating account...", text_color=COLORS["accent"])
        self.update()

        success, msg = self.master.controller.register(username, password)
        if success:
            self.status_label.configure(text="Account created! Redirecting...", text_color=COLORS["success"])
            self.update()
            time.sleep(1)
            self.master.show_login()
        else:
            self.status_label.configure(text=msg, text_color=COLORS["error"])

    def go_to_login(self):
        self.master.show_login()

class MainFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color=COLORS["bg_main"])
        self.master = master
        self.controller = master.controller
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color=COLORS["bg_sidebar"])
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(3, weight=1) 

        # Sidebar Header
        self.logo_label = ctk.CTkLabel(
            self.sidebar, 
            text="SecureChat", 
            font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"),
            text_color=COLORS["accent"]
        )
        self.logo_label.grid(row=0, column=0, padx=25, pady=(35, 10), sticky="w")

        self.user_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.user_frame.grid(row=1, column=0, padx=25, pady=(0, 30), sticky="w")
        
        # User Avatar/Icon (Simple Circle)
        self.avatar = ctk.CTkLabel(
            self.user_frame,
            text=self.controller.username[0].upper(),
            width=35,
            height=35,
            corner_radius=17,
            fg_color=COLORS["accent"],
            text_color=COLORS["bg_main"],
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.avatar.pack(side="left", padx=(0, 10))

        self.user_label = ctk.CTkLabel(
            self.user_frame, 
            text=f"{self.controller.username}", 
            font=ctk.CTkFont(size=16),
            text_color=COLORS["text"]
        )
        self.user_label.pack(side="left")
        
        # Sidebar Actions
        self.create_group_btn = ctk.CTkButton(
            self.sidebar, 
            text="+ New Group", 
            command=self.create_group_dialog,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["bg_main"],
            width=230,
            height=40,
            font=ctk.CTkFont(weight="bold")
        )
        self.create_group_btn.grid(row=2, column=0, padx=25, pady=10)

        # Group List
        self.group_list_label = ctk.CTkLabel(
            self.sidebar, 
            text="YOUR GROUPS", 
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_secondary"]
        )
        self.group_list_label.grid(row=4, column=0, padx=25, pady=(20, 10), sticky="w")

        self.group_list_frame = ctk.CTkScrollableFrame(
            self.sidebar, 
            fg_color="transparent",
            width=230
        )
        self.group_list_frame.grid(row=5, column=0, padx=15, pady=10, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)

        # Bottom Sidebar Actions
        self.check_invites_btn = ctk.CTkButton(
            self.sidebar, 
            text="Check Invites", 
            command=self.check_invites,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["text_secondary"],
            text_color=COLORS["text_secondary"],
            width=230,
            hover_color=COLORS["bg_card"]
        )
        self.check_invites_btn.grid(row=6, column=0, padx=25, pady=10)

        self.logout_btn = ctk.CTkButton(
            self.sidebar, 
            text="Logout", 
            command=self.logout, 
            fg_color="transparent",
            text_color=COLORS["error"],
            hover_color=COLORS["bg_card"],
            width=230,
            anchor="w"
        )
        self.logout_btn.grid(row=7, column=0, padx=25, pady=20)

        # Chat Area
        self.chat_area = ctk.CTkFrame(self, fg_color=COLORS["bg_main"], corner_radius=0)
        self.chat_area.grid(row=0, column=1, sticky="nsew")
        self.chat_area.grid_rowconfigure(1, weight=1)
        self.chat_area.grid_columnconfigure(0, weight=1)

        # Chat Header
        self.chat_header_frame = ctk.CTkFrame(
            self.chat_area, 
            fg_color=COLORS["bg_main"], 
            height=70, 
            corner_radius=0,
            border_width=0,
            border_color=COLORS["border"]
        )
        self.chat_header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        
        # Add a bottom border to header manually if needed, or just use color contrast
        self.header_separator = ctk.CTkFrame(self.chat_area, height=1, fg_color=COLORS["border"])
        self.header_separator.grid(row=0, column=0, sticky="ews", pady=(69,0))

        self.chat_header_label = ctk.CTkLabel(
            self.chat_header_frame, 
            text="Select a group to start chatting", 
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=COLORS["text"]
        )
        self.chat_header_label.pack(side="left", padx=30, pady=20)

        # Messages
        self.messages_frame = ctk.CTkScrollableFrame(
            self.chat_area, 
            fg_color="transparent"
        )
        self.messages_frame.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")

        # Input Area
        self.input_container = ctk.CTkFrame(self.chat_area, fg_color=COLORS["bg_main"], height=80)
        self.input_container.grid(row=2, column=0, sticky="ew", padx=0, pady=0)
        self.input_container.grid_columnconfigure(0, weight=1)

        self.input_frame = ctk.CTkFrame(self.input_container, fg_color=COLORS["bg_sidebar"], corner_radius=25)
        self.input_frame.pack(padx=30, pady=20, fill="x")
        
        self.msg_entry = ctk.CTkEntry(
            self.input_frame, 
            placeholder_text="Type a message...",
            border_width=0,
            fg_color="transparent",
            height=50,
            font=ctk.CTkFont(size=15),
            text_color=COLORS["text"]
        )
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=15)
        self.msg_entry.bind("<Return>", self.send_message)

        self.send_btn = ctk.CTkButton(
            self.input_frame, 
            text="Send", 
            width=80, 
            height=40,
            command=self.send_message,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["bg_main"],
            corner_radius=20,
            font=ctk.CTkFont(weight="bold")
        )
        self.send_btn.pack(side="right", padx=5, pady=5)

        self.current_group = None
        self.displayed_message_count = 0
        self.running = True
        
        self.load_groups()
        
        # Start background update thread
        self.update_thread = threading.Thread(target=self.background_update, daemon=True)
        self.update_thread.start()

    def logout(self):
        self.running = False
        self.controller.logout()
        self.master.show_login()

    def load_groups(self):
        for widget in self.group_list_frame.winfo_children():
            widget.destroy()
        
        groups = self.controller.get_groups()
        for group in groups:
            is_selected = self.current_group == group
            btn = ctk.CTkButton(
                self.group_list_frame, 
                text=f"# {group}", 
                command=lambda g=group: self.select_group(g),
                fg_color=COLORS["bg_card"] if is_selected else "transparent",
                text_color=COLORS["text"] if is_selected else COLORS["text_secondary"],
                hover_color=COLORS["bg_card"],
                anchor="w",
                height=45,
                corner_radius=8
            )
            btn.pack(pady=2, padx=5, fill="x")

    def select_group(self, group_name):
        self.current_group = group_name
        self.chat_header_label.configure(text=f"# {group_name}")
        
        # Update selection visual
        self.load_groups()
        
        # Reset message count and clear frame when switching groups
        self.displayed_message_count = 0
        for widget in self.messages_frame.winfo_children():
            widget.destroy()
        self.refresh_messages()

    def refresh_messages(self):
        if not self.current_group: return
        
        messages = self.controller.get_messages(self.current_group)
        total_messages = len(messages)
        
        if total_messages > self.displayed_message_count:
            # Only add new messages
            for i in range(self.displayed_message_count, total_messages):
                sender, msg = messages[i]
                self.display_message(sender, msg)
            
            self.displayed_message_count = total_messages
            # Scroll to bottom
            self.messages_frame._parent_canvas.yview_moveto(1.0)

    def display_message(self, sender, msg):
        is_me = sender == self.controller.username
        
        container = ctk.CTkFrame(self.messages_frame, fg_color="transparent")
        container.pack(fill="x", pady=5)
        
        bubble_color = COLORS["bubble_me"] if is_me else COLORS["bubble_other"]
        text_color = COLORS["text"]
        anchor = "e" if is_me else "w"
        
        # Message Bubble
        bubble = ctk.CTkFrame(container, fg_color=bubble_color, corner_radius=15)
        bubble.pack(anchor=anchor, padx=20, ipadx=10, ipady=5)
        
        # Sender Name (only for others)
        if not is_me:
            name_lbl = ctk.CTkLabel(
                bubble, 
                text=sender, 
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=COLORS["accent"]
            )
            name_lbl.pack(anchor="w", padx=10, pady=(5, 0))

        # Message Text
        msg_lbl = ctk.CTkLabel(
            bubble, 
            text=msg, 
            text_color=text_color, 
            font=ctk.CTkFont(size=14),
            wraplength=450,
            justify="left"
        )
        msg_lbl.pack(padx=10, pady=5)

    def send_message(self, event=None):
        if not self.current_group: return
        text = self.msg_entry.get()
        if not text: return
        
        if self.controller.send_group_message(self.current_group, text):
            self.msg_entry.delete(0, "end")
            self.refresh_messages()

    def create_group_dialog(self):
        dialog = ctk.CTkInputDialog(text="Enter group name:", title="Create Group")
        group_name = dialog.get_input()
        if group_name:
            dialog2 = ctk.CTkInputDialog(text="Enter initial member username:", title="Add Member")
            member = dialog2.get_input()
            if member:
                success, msg = self.controller.create_group(group_name, member)
                if success:
                    self.load_groups()
                else:
                    print(msg) # Ideally show in UI

    def check_invites(self):
        invites = self.controller.check_invitations()
        if invites:
            for invite in invites:
                self.show_invite_dialog(invite)
        else:
            pass # No invites

    def show_invite_dialog(self, invite):
        # Simplified: just accept
        if self.controller.accept_invitation(invite):
            self.load_groups()

    def background_update(self):
        while self.running:
            if self.current_group:
                self.controller.check_for_updates()
                # Schedule UI update on main thread
                self.after(0, self.refresh_messages)
            time.sleep(2)

if __name__ == "__main__":
    app = App()
    app.mainloop()
