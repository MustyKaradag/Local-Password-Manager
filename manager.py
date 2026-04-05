import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import secrets
import string
import sqlite3
import os
import sys
import base64
import json
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# --- Path Setup ---
appdata_path = os.getenv('APPDATA') 
app_folder = os.path.join(appdata_path, 'LocalPasswordManager')

if not os.path.exists(app_folder):
    os.makedirs(app_folder)

DB_PATH = os.path.join(app_folder, 'passwords.db')
SALT_PATH = os.path.join(app_folder, 'salt.key')
VERIFY_PATH = os.path.join(app_folder, 'verify.key')

cipher_suite = None

# --- Security Functions ---
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def authenticate():
    global cipher_suite
    
    if not os.path.exists(SALT_PATH) or not os.path.exists(VERIFY_PATH):
        messagebox.showinfo("Welcome", "Let's secure your vault. Create a Master Password.\n\nKEEP THIS SAFE. If you lose it, your passwords are gone forever!")
        pwd = simpledialog.askstring("Setup", "Create Master Password:", show='*')
        if not pwd:
            return False
            
        salt = os.urandom(16)
        with open(SALT_PATH, 'wb') as f:
            f.write(salt)
            
        key = derive_key(pwd, salt)
        f_cipher = Fernet(key)
        
        token = f_cipher.encrypt(b"valid_password")
        with open(VERIFY_PATH, 'wb') as f:
            f.write(token)
            
        cipher_suite = f_cipher
        return True
        
    else:
        with open(SALT_PATH, 'rb') as f:
            salt = f.read()
        with open(VERIFY_PATH, 'rb') as f:
            verify_token = f.read()
            
        while True:
            pwd = simpledialog.askstring("Login", "Enter Master Password:", show='*')
            if pwd is None: 
                return False
                
            key = derive_key(pwd, salt)
            f_cipher = Fernet(key)
            
            try:
                if f_cipher.decrypt(verify_token) == b"valid_password":
                    cipher_suite = f_cipher
                    return True
            except InvalidToken:
                messagebox.showerror("Error", "Incorrect Master Password!")

def verify_master_password():
    """Prompts for the Master Password to authorize an action."""
    pwd = simpledialog.askstring("Security Check", "Enter Master Password to copy:", show='*')
    if not pwd: 
        return False
        
    with open(SALT_PATH, 'rb') as f:
        salt = f.read()
    with open(VERIFY_PATH, 'rb') as f:
        verify_token = f.read()
        
    key = derive_key(pwd, salt)
    f_cipher = Fernet(key)
    
    try:
        if f_cipher.decrypt(verify_token) == b"valid_password":
            return True
    except InvalidToken:
        pass
        
    messagebox.showerror("Error", "Incorrect Master Password!")
    return False

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# --- Core App Functions ---
def generate_password():
    length = length_var.get()
    char_pool = ""
    if upper_var.get(): char_pool += string.ascii_uppercase
    if lower_var.get(): char_pool += string.ascii_lowercase
    if num_var.get(): char_pool += string.digits
    if sym_var.get(): char_pool += string.punctuation
        
    if not char_pool:
        messagebox.showwarning("Warning", "Select at least one character type!")
        return

    password = ''.join(secrets.choice(char_pool) for _ in range(length))
    password_display.config(state="normal")
    password_display.delete(0, tk.END)
    password_display.insert(0, password)
    password_display.config(state="readonly")

def save_password():
    website = website_entry.get()
    username = username_entry.get()
    password = password_display.get()

    if not website or not username or not password:
        messagebox.showwarning("Warning", "Please fill in all fields!")
        return

    encrypted_password = cipher_suite.encrypt(password.encode()).decode()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO credentials (website, username, password) VALUES (?, ?, ?)", 
                   (website, username, encrypted_password))
    conn.commit()
    conn.close()

    messagebox.showinfo("Success", f"Password for {website} encrypted and saved!")
    
    website_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_display.config(state="normal")
    password_display.delete(0, tk.END)
    password_display.config(state="readonly")
    load_passwords()

def update_length_label(event):
    length_label.config(text=f"Password Length: {length_var.get()}")

def load_passwords(*args):
    for row in tree.get_children():
        tree.delete(row)
        
    search_query = search_var.get()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if search_query:
        cursor.execute("SELECT id, website, username FROM credentials WHERE website LIKE ? OR username LIKE ?", 
                       ('%' + search_query + '%', '%' + search_query + '%'))
    else:
        cursor.execute("SELECT id, website, username FROM credentials")
        
    for row in cursor.fetchall():
        record_id, website, username = row
        # Insert masked string instead of real password into the table view
        tree.insert("", "end", values=(record_id, website, username, "********"))
        
    conn.close()

def popup_menu(event):
    iid = tree.identify_row(event.y)
    if iid:
        tree.selection_set(iid)
        menu.tk_popup(event.x_root, event.y_root)

def delete_password():
    selected = tree.selection()
    if not selected: return
    record_id = tree.item(selected[0])['values'][0]
    
    if messagebox.askyesno("Confirm", "Delete this saved password?"):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE id=?", (record_id,))
        conn.commit()
        conn.close()
        load_passwords()

def edit_password():
    selected = tree.selection()
    if not selected: return
    
    item = tree.item(selected[0])
    record_id, website, username, _ = item['values']
    
    # Fetch real password from DB for the edit window
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM credentials WHERE id=?", (record_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row: return
    real_password = cipher_suite.decrypt(row[0].encode()).decode()
    
    edit_win = tk.Toplevel(root)
    edit_win.title("Edit Entry")
    edit_win.geometry("300x250")
    edit_win.configure(padx=20, pady=20)
    
    ttk.Label(edit_win, text="Website:", font=("Arial", 9, "bold")).pack(anchor="w", pady=(0, 2))
    web_entry = ttk.Entry(edit_win, width=30)
    web_entry.insert(0, website)
    web_entry.pack(fill="x", pady=(0, 10))
    
    ttk.Label(edit_win, text="Username:", font=("Arial", 9, "bold")).pack(anchor="w", pady=(0, 2))
    usr_entry = ttk.Entry(edit_win, width=30)
    usr_entry.insert(0, username)
    usr_entry.pack(fill="x", pady=(0, 10))
    
    ttk.Label(edit_win, text="Password:", font=("Arial", 9, "bold")).pack(anchor="w", pady=(0, 2))
    pwd_entry = ttk.Entry(edit_win, width=30)
    pwd_entry.insert(0, real_password)
    pwd_entry.pack(fill="x", pady=(0, 15))
    
    def save_changes():
        new_enc_pwd = cipher_suite.encrypt(pwd_entry.get().encode()).decode()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE credentials SET website=?, username=?, password=? WHERE id=?", 
                       (web_entry.get(), usr_entry.get(), new_enc_pwd, record_id))
        conn.commit()
        conn.close()
        edit_win.destroy()
        load_passwords()
        
    ttk.Button(edit_win, text="Save Changes", command=save_changes).pack(fill="x")

# --- UI Helper Features ---
def copy_to_clipboard(text, btn_widget):
    root.clipboard_clear()
    root.clipboard_append(text)
    original_text = btn_widget.cget("text")
    btn_widget.config(text="Copied!")
    root.after(1500, lambda: btn_widget.config(text=original_text))

def toggle_gen_view():
    if password_display.cget("show") == "*":
        password_display.config(show="")
        btn_show_gen.config(text="Hide")
    else:
        password_display.config(show="*")
        btn_show_gen.config(text="Show")

def view_password_details(event):
    selected = tree.selection()
    if not selected: return
    
    item = tree.item(selected[0])
    record_id, website, username, _ = item['values']
    
    # Fetch real password for copying functionality
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM credentials WHERE id=?", (record_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row: return
    real_password = cipher_suite.decrypt(row[0].encode()).decode()
    
    view_win = tk.Toplevel(root)
    view_win.title(f"Details: {website}")
    view_win.geometry("400x250")
    view_win.configure(padx=20, pady=20)
    
    ttk.Label(view_win, text=f"Website: {website}", font=("Arial", 12, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 15))
    
    ttk.Label(view_win, text="Username:", font=("Arial", 9, "bold")).grid(row=1, column=0, sticky="w", pady=(0, 5))
    usr_entry = ttk.Entry(view_win, width=30, state="readonly")
    usr_entry.config(state="normal")
    usr_entry.insert(0, username)
    usr_entry.config(state="readonly")
    usr_entry.grid(row=2, column=0, sticky="w", pady=(0, 15))
    
    btn_copy_usr = ttk.Button(view_win, text="Copy User")
    btn_copy_usr.config(command=lambda b=btn_copy_usr: copy_to_clipboard(username, b))
    btn_copy_usr.grid(row=2, column=1, padx=(10, 0), pady=(0, 15))
    
    # Password field is masked in the details view as well
    ttk.Label(view_win, text="Password:", font=("Arial", 9, "bold")).grid(row=3, column=0, sticky="w", pady=(0, 5))
    pwd_entry = ttk.Entry(view_win, width=30, state="readonly", show="*")
    pwd_entry.config(state="normal")
    pwd_entry.insert(0, real_password)
    pwd_entry.config(state="readonly")
    pwd_entry.grid(row=4, column=0, sticky="w", pady=(0, 15))
    
    def secure_copy():
        if verify_master_password():
            copy_to_clipboard(real_password, btn_copy_pwd)
            view_win.destroy() # Closes details window after successful copy

    btn_copy_pwd = ttk.Button(view_win, text="Copy Pass", command=secure_copy)
    btn_copy_pwd.grid(row=4, column=1, padx=(10, 0), pady=(0, 15))

# --- Export & Import ---
def export_vault():
    file_path = filedialog.asksaveasfilename(defaultextension=".vault", filetypes=[("Vault Backup", "*.vault")], title="Save Backup File")
    if not file_path: return

    backup_pwd = simpledialog.askstring("Backup Password", "Create a password to lock this backup file:\n(You will need this to import it later!)", show='*')
    if not backup_pwd: return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT website, username, password FROM credentials")
    rows = cursor.fetchall()
    conn.close()

    export_data = []
    for web, usr, enc_pwd in rows:
        try:
            dec_pwd = cipher_suite.decrypt(enc_pwd.encode()).decode()
            export_data.append({"website": web, "username": usr, "password": dec_pwd})
        except Exception:
            continue

    json_data = json.dumps(export_data).encode()
    salt = os.urandom(16)
    key = derive_key(backup_pwd, salt)
    f_cipher = Fernet(key)
    encrypted_payload = f_cipher.encrypt(json_data)

    with open(file_path, 'wb') as f:
        f.write(salt + encrypted_payload)

    messagebox.showinfo("Success", "Vault successfully backed up and heavily encrypted!")

def import_vault():
    file_path = filedialog.askopenfilename(filetypes=[("Vault Backup", "*.vault")], title="Select Backup File")
    if not file_path: return

    backup_pwd = simpledialog.askstring("Backup Password", "Enter the password for this backup file:", show='*')
    if not backup_pwd: return

    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        salt = data[:16]
        encrypted_payload = data[16:]
        key = derive_key(backup_pwd, salt)
        f_cipher = Fernet(key)
        decrypted_json = f_cipher.decrypt(encrypted_payload)
        
        import_data = json.loads(decrypted_json)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        imported_count = 0
        
        for item in import_data:
            web = item.get("website")
            usr = item.get("username")
            pwd = item.get("password")

            if web and usr and pwd:
                new_enc_pwd = cipher_suite.encrypt(pwd.encode()).decode()
                cursor.execute("INSERT INTO credentials (website, username, password) VALUES (?, ?, ?)", (web, usr, new_enc_pwd))
                imported_count += 1

        conn.commit()
        conn.close()
        load_passwords()
        messagebox.showinfo("Success", f"Successfully imported {imported_count} passwords into your vault!")

    except Exception:
        messagebox.showerror("Error", "Failed to import! The password was incorrect or the file is corrupted.")

# --- UI Setup & Startup Flow ---
root = tk.Tk()
root.withdraw() 

if not authenticate():
    sys.exit() 

root.deiconify() 
root.title("Local Password Manager v1.4") 
root.geometry("600x480")

init_db()

# Tabs
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=10, pady=10)

tab_generator = ttk.Frame(notebook)
tab_vault = ttk.Frame(notebook)
tab_sync = ttk.Frame(notebook) 
tab_about = ttk.Frame(notebook) 

notebook.add(tab_generator, text="Generator & Save")
notebook.add(tab_vault, text="Saved Passwords")
notebook.add(tab_sync, text="Backup & Restore") 
notebook.add(tab_about, text="About") 

# ==========================================
# TAB 1: GENERATOR
# ==========================================
tab_generator.configure(padding=20)
length_var = tk.IntVar(value=16)
upper_var, lower_var, num_var, sym_var = tk.BooleanVar(value=True), tk.BooleanVar(value=True), tk.BooleanVar(value=True), tk.BooleanVar(value=True)

ttk.Label(tab_generator, text="Website / App:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 5))
website_entry = ttk.Entry(tab_generator, width=30)
website_entry.grid(row=0, column=1, columnspan=4, sticky="w", pady=(0, 5))

ttk.Label(tab_generator, text="Username / Email:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky="w", pady=(0, 15))
username_entry = ttk.Entry(tab_generator, width=30)
username_entry.grid(row=1, column=1, columnspan=4, sticky="w", pady=(0, 15))

ttk.Separator(tab_generator, orient='horizontal').grid(row=2, column=0, columnspan=5, sticky="ew", pady=10)

length_label = ttk.Label(tab_generator, text=f"Password Length: {length_var.get()}", font=("Arial", 10, "bold"))
length_label.grid(row=3, column=0, sticky="w", pady=(0, 10))
length_slider = ttk.Scale(tab_generator, from_=8, to_=64, orient="horizontal", variable=length_var, command=update_length_label)
length_slider.grid(row=3, column=1, columnspan=4, sticky="ew", pady=(0, 10))

ttk.Label(tab_generator, text="Characters Used:", font=("Arial", 10, "bold")).grid(row=4, column=0, sticky="w", pady=10)
ttk.Checkbutton(tab_generator, text="Uppercase", variable=upper_var).grid(row=4, column=1, sticky="w")
ttk.Checkbutton(tab_generator, text="Lowercase", variable=lower_var).grid(row=4, column=2, sticky="w")
ttk.Checkbutton(tab_generator, text="Numbers", variable=num_var).grid(row=4, column=3, sticky="w")
ttk.Checkbutton(tab_generator, text="Symbols", variable=sym_var).grid(row=4, column=4, sticky="w")

generate_btn = ttk.Button(tab_generator, text="Generate Password", command=generate_password)
generate_btn.grid(row=5, column=0, columnspan=5, pady=(15, 5))

gen_action_frame = ttk.Frame(tab_generator)
gen_action_frame.grid(row=6, column=0, columnspan=5, sticky="ew", pady=(0, 15))

password_display = ttk.Entry(gen_action_frame, font=("Courier", 12), justify="center", state="readonly", show="*")
password_display.pack(side="left", fill="x", expand=True, padx=(0, 5))

btn_copy_gen = ttk.Button(gen_action_frame, text="Copy", command=lambda: copy_to_clipboard(password_display.get(), btn_copy_gen) if password_display.get() else None)
btn_copy_gen.pack(side="left", padx=(0, 5))

btn_show_gen = ttk.Button(gen_action_frame, text="Show", command=toggle_gen_view)
btn_show_gen.pack(side="left")

save_btn = ttk.Button(tab_generator, text="Encrypt & Save", command=save_password)
save_btn.grid(row=7, column=0, columnspan=5, pady=5)

for i in range(1, 5): tab_generator.columnconfigure(i, weight=1)

# ==========================================
# TAB 2: VAULT
# ==========================================
search_frame = ttk.Frame(tab_vault)
search_frame.pack(fill="x", padx=10, pady=10)
ttk.Label(search_frame, text="Search Vault:", font=("Arial", 10, "bold")).pack(side="left")
search_var = tk.StringVar()
search_var.trace("w", load_passwords) 
search_entry = ttk.Entry(search_frame, textvariable=search_var)
search_entry.pack(side="left", fill="x", expand=True, padx=10)

columns = ("ID", "Website", "Username", "Password")
tree = ttk.Treeview(tab_vault, columns=columns, show="headings")
tree.heading("ID", text="ID")
tree.heading("Website", text="Website / App")
tree.heading("Username", text="Username / Email")
tree.heading("Password", text="Password")
tree.column("ID", width=0, stretch=tk.NO)
tree.column("Website", width=150)
tree.column("Username", width=200)
tree.column("Password", width=200)
tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

menu = tk.Menu(root, tearoff=0)
menu.add_command(label="Edit Entry", command=edit_password)
menu.add_command(label="Delete Entry", command=delete_password)
tree.bind("<Button-3>", popup_menu)
tree.bind("<Double-1>", view_password_details) 

load_passwords()

# ==========================================
# TAB 3: BACKUP & RESTORE
# ==========================================
tab_sync.configure(padding=40)

ttk.Label(tab_sync, text="Export Encrypted Backup", font=("Arial", 12, "bold")).pack(anchor="w", pady=(0, 5))
ttk.Label(tab_sync, text="Save a secure .vault file to your PC or a USB drive.\nYou will set a specific password to lock this file.", font=("Arial", 10)).pack(anchor="w", pady=(0, 10))
btn_export = ttk.Button(tab_sync, text="Export Vault...", command=export_vault)
btn_export.pack(anchor="w", pady=(0, 30))

ttk.Label(tab_sync, text="Import Backup", font=("Arial", 12, "bold")).pack(anchor="w", pady=(0, 5))
ttk.Label(tab_sync, text="Load a .vault file. The passwords will be instantly merged\nand re-encrypted to match your current Master Password.", font=("Arial", 10)).pack(anchor="w", pady=(0, 10))
btn_import = ttk.Button(tab_sync, text="Import Vault...", command=import_vault)
btn_import.pack(anchor="w")

# ==========================================
# TAB 4: ABOUT
# ==========================================
tab_about.configure(padding=40)

ttk.Label(tab_about, text="Local Password Manager", font=("Arial", 16, "bold")).pack(pady=(10, 5))
ttk.Label(tab_about, text="Version 1.4", font=("Arial", 10)).pack(pady=(0, 20))

ttk.Label(tab_about, text="A lightweight, secure, and entirely offline vault.", font=("Arial", 10)).pack(pady=(0, 10))
ttk.Label(tab_about, text="100% Free and Open-Source.", font=("Arial", 10, "italic")).pack(pady=(0, 30))

ttk.Label(tab_about, text="Created by Mustafa Karadağ", font=("Arial", 11, "bold")).pack(pady=(10, 5))
ttk.Label(tab_about, text="Thank you for using this app!", font=("Arial", 10)).pack()

root.mainloop()