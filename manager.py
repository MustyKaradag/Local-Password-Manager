import tkinter as tk
from tkinter import ttk, messagebox
import secrets
import string
import sqlite3
import os

# --- Path Setup ---
appdata_path = os.getenv('APPDATA') 
app_folder = os.path.join(appdata_path, 'LocalPasswordManager')

if not os.path.exists(app_folder):
    os.makedirs(app_folder)

DB_PATH = os.path.join(app_folder, 'passwords.db')

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

# --- Functions ---
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
        messagebox.showwarning("Warning", "Please fill in the Website, Username, and generate a Password!")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO credentials (website, username, password) VALUES (?, ?, ?)", 
                   (website, username, password))
    conn.commit()
    conn.close()

    messagebox.showinfo("Success", f"Password for {website} saved successfully!")
    
    website_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_display.config(state="normal")
    password_display.delete(0, tk.END)
    password_display.config(state="readonly")
    
    load_passwords()

def update_length_label(event):
    length_label.config(text=f"Password Length: {length_var.get()}")

def load_passwords(*args):
    # Clear the current table view
    for row in tree.get_children():
        tree.delete(row)
        
    search_query = search_var.get()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # We now fetch the 'id' as well, so we know exactly which record to edit/delete
    if search_query:
        cursor.execute("SELECT id, website, username, password FROM credentials WHERE website LIKE ? OR username LIKE ?", 
                       ('%' + search_query + '%', '%' + search_query + '%'))
    else:
        cursor.execute("SELECT id, website, username, password FROM credentials")
        
    for row in cursor.fetchall():
        tree.insert("", "end", values=row)
        
    conn.close()

# --- Right Click Menu Functions ---
def popup_menu(event):
    """Selects the row under the mouse and shows the right-click menu."""
    iid = tree.identify_row(event.y)
    if iid:
        tree.selection_set(iid)
        menu.tk_popup(event.x_root, event.y_root)

def delete_password():
    selected = tree.selection()
    if not selected:
        return
    
    item = tree.item(selected[0])
    record_id = item['values'][0] # Get the hidden database ID
    
    if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this saved password?"):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE id=?", (record_id,))
        conn.commit()
        conn.close()
        load_passwords()

def edit_password():
    selected = tree.selection()
    if not selected:
        return
    
    item = tree.item(selected[0])
    record_id, website, username, password = item['values']
    
    # Create a small popup window
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
    pwd_entry.insert(0, password)
    pwd_entry.pack(fill="x", pady=(0, 15))
    
    def save_changes():
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE credentials SET website=?, username=?, password=? WHERE id=?", 
                       (web_entry.get(), usr_entry.get(), pwd_entry.get(), record_id))
        conn.commit()
        conn.close()
        edit_win.destroy()
        load_passwords()
        
    ttk.Button(edit_win, text="Save Changes", command=save_changes).pack(fill="x")

# Initialize the database
init_db()

# --- UI Setup ---
root = tk.Tk()
root.title("Local Password Manager")
root.geometry("600x450")

# Setup Tabs
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=10, pady=10)

tab_generator = ttk.Frame(notebook)
tab_vault = ttk.Frame(notebook)

notebook.add(tab_generator, text="Generator & Save")
notebook.add(tab_vault, text="Saved Passwords")

# ==========================================
# TAB 1: GENERATOR & SAVE
# ==========================================
tab_generator.configure(padding=20)

length_var = tk.IntVar(value=16)
upper_var = tk.BooleanVar(value=True)
lower_var = tk.BooleanVar(value=True)
num_var = tk.BooleanVar(value=True)
sym_var = tk.BooleanVar(value=True)

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

password_display = ttk.Entry(tab_generator, font=("Courier", 12), justify="center", state="readonly")
password_display.grid(row=6, column=0, columnspan=5, sticky="ew", pady=(0, 15))

save_btn = ttk.Button(tab_generator, text="Save to Database", command=save_password)
save_btn.grid(row=7, column=0, columnspan=5, pady=5)

for i in range(1, 5):
    tab_generator.columnconfigure(i, weight=1)

# ==========================================
# TAB 2: SAVED PASSWORDS (VAULT)
# ==========================================
search_frame = ttk.Frame(tab_vault)
search_frame.pack(fill="x", padx=10, pady=10)

ttk.Label(search_frame, text="Search Vault:", font=("Arial", 10, "bold")).pack(side="left")

search_var = tk.StringVar()
search_var.trace("w", load_passwords) 
search_entry = ttk.Entry(search_frame, textvariable=search_var)
search_entry.pack(side="left", fill="x", expand=True, padx=10)

# Treeview with hidden ID column
columns = ("ID", "Website", "Username", "Password")
tree = ttk.Treeview(tab_vault, columns=columns, show="headings")

tree.heading("ID", text="ID")
tree.heading("Website", text="Website / App")
tree.heading("Username", text="Username / Email")
tree.heading("Password", text="Password")

# Hide the ID column but keep it accessible for the edit/delete functions
tree.column("ID", width=0, stretch=tk.NO)
tree.column("Website", width=150)
tree.column("Username", width=200)
tree.column("Password", width=200)

tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

# Create the Right-Click Menu
menu = tk.Menu(root, tearoff=0)
menu.add_command(label="Edit Entry", command=edit_password)
menu.add_command(label="Delete Entry", command=delete_password)

# Bind the right-click button (Button-3 on Windows) to the table
tree.bind("<Button-3>", popup_menu)

# Load data into the table
load_passwords()

root.mainloop()