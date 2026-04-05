import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import secrets
import string
import sqlite3
import os
import sys
import base64
import json
import csv
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
CONFIG_PATH = os.path.join(app_folder, 'config.json')

cipher_suite = None
lock_timer_id = None
clipboard_timer_id = None

# --- Configuration (Memory) ---
def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {"language": "English"}

def save_config(lang):
    with open(CONFIG_PATH, 'w') as f:
        json.dump({"language": lang}, f)

# --- Security Functions ---
def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def authenticate():
    global cipher_suite
    if not os.path.exists(SALT_PATH) or not os.path.exists(VERIFY_PATH):
        messagebox.showinfo("Welcome", "Let's secure your vault. Create a Master Password.\n\nKEEP THIS SAFE. If you lose it, your passwords are gone forever!")
        pwd = simpledialog.askstring("Setup", "Create Master Password:", show='*')
        if not pwd: return False
        salt = os.urandom(16)
        with open(SALT_PATH, 'wb') as f: f.write(salt)
        key = derive_key(pwd, salt)
        f_cipher = Fernet(key)
        token = f_cipher.encrypt(b"valid_password")
        with open(VERIFY_PATH, 'wb') as f: f.write(token)
        cipher_suite = f_cipher
        return True
    else:
        with open(SALT_PATH, 'rb') as f: salt = f.read()
        with open(VERIFY_PATH, 'rb') as f: verify_token = f.read()
        while True:
            pwd = simpledialog.askstring("Login", "Enter Master Password:", show='*')
            if pwd is None: return False
            key = derive_key(pwd, salt)
            f_cipher = Fernet(key)
            try:
                if f_cipher.decrypt(verify_token) == b"valid_password":
                    cipher_suite = f_cipher
                    return True
            except InvalidToken:
                messagebox.showerror("Error", "Incorrect Master Password!")

def verify_master_password():
    pwd = simpledialog.askstring("Security Check", "Enter Master Password:", show='*')
    if not pwd: return False
    with open(SALT_PATH, 'rb') as f: salt = f.read()
    with open(VERIFY_PATH, 'rb') as f: verify_token = f.read()
    key = derive_key(pwd, salt)
    f_cipher = Fernet(key)
    try:
        if f_cipher.decrypt(verify_token) == b"valid_password": return True
    except InvalidToken:
        pass
    messagebox.showerror("Error", "Incorrect Master Password!")
    return False

# --- Auto-Lock Timer ---
def lock_app():
    root.withdraw()
    if authenticate():
        root.deiconify()
        reset_lock_timer()
    else:
        sys.exit()

def reset_lock_timer(event=None):
    global lock_timer_id
    if lock_timer_id: root.after_cancel(lock_timer_id)
    lock_timer_id = root.after(120000, lock_app) 

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS credentials 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, website TEXT NOT NULL, username TEXT NOT NULL, password TEXT NOT NULL)''')
    try: # Safely upgrade existing database
        cursor.execute("ALTER TABLE credentials ADD COLUMN notes TEXT DEFAULT ''")
    except Exception: pass
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
    notes = notes_entry.get("1.0", tk.END).strip()
    
    if not website or not username or not password:
        messagebox.showwarning("Warning", "Please fill in all required fields!")
        return
        
    encrypted_password = cipher_suite.encrypt(password.encode()).decode()
    encrypted_notes = cipher_suite.encrypt(notes.encode()).decode() if notes else ""

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO credentials (website, username, password, notes) VALUES (?, ?, ?, ?)", 
                   (website, username, encrypted_password, encrypted_notes))
    conn.commit(); conn.close()
    
    messagebox.showinfo("Success", f"Password for {website} encrypted and saved!")
    website_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    notes_entry.delete("1.0", tk.END) # Clears notes box
    password_display.config(state="normal")
    password_display.delete(0, tk.END)
    password_display.config(state="readonly")
    load_passwords()

def load_passwords(*args):
    for row in tree.get_children(): tree.delete(row)
    search_query = search_var.get()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if search_query:
        cursor.execute("SELECT id, website, username FROM credentials WHERE website LIKE ? OR username LIKE ?", ('%' + search_query + '%', '%' + search_query + '%'))
    else:
        cursor.execute("SELECT id, website, username FROM credentials")
    for row in cursor.fetchall():
        record_id, website, username = row
        tree.insert("", "end", values=(record_id, website, username, "********"))
    conn.close()

def delete_password():
    selected = tree.selection()
    if not selected: return
    record_id = tree.item(selected[0])['values'][0]
    if messagebox.askyesno("Confirm", "Delete this saved password?"):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE id=?", (record_id,))
        conn.commit(); conn.close()
        load_passwords()

def edit_password():
    selected = tree.selection()
    if not selected: return
    if not verify_master_password(): return
    item = tree.item(selected[0])
    record_id, website, username, _ = item['values']
    
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
    pwd_entry = ttk.Entry(edit_win, width=30, show="*")
    pwd_entry.insert(0, real_password)
    pwd_entry.pack(fill="x", pady=(0, 15))
    
    def save_changes():
        new_enc_pwd = cipher_suite.encrypt(pwd_entry.get().encode()).decode()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE credentials SET website=?, username=?, password=? WHERE id=?", (web_entry.get(), usr_entry.get(), new_enc_pwd, record_id))
        conn.commit(); conn.close()
        edit_win.destroy()
        load_passwords()
        
    ttk.Button(edit_win, text="Save Changes", command=save_changes).pack(fill="x")

def popup_menu(event):
    iid = tree.identify_row(event.y)
    if iid:
        tree.selection_set(iid)
        menu.tk_popup(event.x_root, event.y_root)

def copy_to_clipboard(text, btn_widget):
    global clipboard_timer_id
    root.clipboard_clear()
    root.clipboard_append(text)
    
    original_text = btn_widget.cget("text")
    btn_widget.config(text="✓") 
    root.after(1500, lambda: btn_widget.config(text=original_text))
    
    if clipboard_timer_id: root.after_cancel(clipboard_timer_id)
    clipboard_timer_id = root.after(30000, root.clipboard_clear)

def toggle_gen_view():
    lang = lang_var.get()
    trans = LANGUAGES.get(lang, LANGUAGES["English"])
    if password_display.cget("show") == "*":
        password_display.config(show="")
        btn_show_gen.config(text=trans["btn_hid"])
    else:
        password_display.config(show="*")
        btn_show_gen.config(text=trans["btn_shw"])

def update_strength(*args):
    lang = lang_var.get()
    trans = LANGUAGES.get(lang, LANGUAGES["English"])
    length = length_var.get()
    lbl_length.config(text=f"{trans['len']}{length}")
    
    types = sum([upper_var.get(), lower_var.get(), num_var.get(), sym_var.get()])
    if types == 0:
        strength_bar['value'] = 0
        strength_lbl.config(text="Strength: Invalid", foreground="red")
        return
        
    score = length * types
    if score < 20:
        strength_bar['value'] = 25
        strength_lbl.config(text="Strength: Weak", foreground="red")
    elif score < 40:
        strength_bar['value'] = 50
        strength_lbl.config(text="Strength: Fair", foreground="darkorange")
    elif score < 60:
        strength_bar['value'] = 75
        strength_lbl.config(text="Strength: Good", foreground="blue")
    else:
        strength_bar['value'] = 100
        strength_lbl.config(text="Strength: Strong", foreground="green")

def view_password_details(event):
    selected = tree.selection()
    if not selected: return
    item = tree.item(selected[0])
    record_id, website, username, _ = item['values']
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT password, notes FROM credentials WHERE id=?", (record_id,))
    row = cursor.fetchone()
    conn.close()
    if not row: return
    
    real_password = cipher_suite.decrypt(row[0].encode()).decode()
    real_notes = cipher_suite.decrypt(row[1].encode()).decode() if (len(row) > 1 and row[1]) else ""
    
    view_win = tk.Toplevel(root)
    view_win.title(f"Details: {website}")
    view_win.geometry("450x350")
    view_win.configure(padx=20, pady=20)
    
    ttk.Label(view_win, text=f"Website: {website}", font=("Arial", 12, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 15))
    ttk.Label(view_win, text="Username:", font=("Arial", 9, "bold")).grid(row=1, column=0, sticky="w", pady=(0, 5))
    usr_entry = ttk.Entry(view_win, width=35, state="readonly")
    usr_entry.config(state="normal"); usr_entry.insert(0, username); usr_entry.config(state="readonly")
    usr_entry.grid(row=2, column=0, sticky="w", pady=(0, 15))
    
    btn_copy_usr = ttk.Button(view_win, text="Copy", command=lambda: copy_to_clipboard(username, btn_copy_usr))
    btn_copy_usr.grid(row=2, column=1, padx=(10, 0), pady=(0, 15))
    
    ttk.Label(view_win, text="Password:", font=("Arial", 9, "bold")).grid(row=3, column=0, sticky="w", pady=(0, 5))
    pwd_entry = ttk.Entry(view_win, width=35, state="readonly", show="*")
    pwd_entry.config(state="normal"); pwd_entry.insert(0, real_password); pwd_entry.config(state="readonly")
    pwd_entry.grid(row=4, column=0, sticky="w", pady=(0, 15))
    
    def secure_copy():
        if verify_master_password():
            copy_to_clipboard(real_password, btn_copy_pwd)
            view_win.destroy()

    btn_copy_pwd = ttk.Button(view_win, text="Copy", command=secure_copy)
    btn_copy_pwd.grid(row=4, column=1, padx=(10, 0), pady=(0, 15))
    
    ttk.Label(view_win, text="Secure Notes:", font=("Arial", 9, "bold")).grid(row=5, column=0, sticky="w", pady=(0, 5))
    notes_box = tk.Text(view_win, height=4, width=35, font=("Arial", 10))
    notes_box.insert("1.0", real_notes if real_notes else "No notes saved.")
    notes_box.config(state="disabled")
    notes_box.grid(row=6, column=0, columnspan=2, sticky="w")

def audit_vault():
    if not verify_master_password(): return
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT website, password FROM credentials")
    rows = cursor.fetchall()
    conn.close()
    
    passwords_seen = {}
    reused = set()
    weak = []
    
    for web, enc_pwd in rows:
        try:
            pwd = cipher_suite.decrypt(enc_pwd.encode()).decode()
            if len(pwd) < 10: weak.append(web)
            if pwd in passwords_seen:
                reused.add(web)
                reused.add(passwords_seen[pwd])
            passwords_seen[pwd] = web
        except: continue
        
    msg = "🛡️ VAULT HEALTH REPORT 🛡️\n\n"
    msg += f"Total Passwords: {len(rows)}\n\n"
    msg += f"Weak Passwords (<10 chars): {len(weak)}\n" + (", ".join(weak) if weak else "None! Excellent.") + "\n\n"
    msg += f"Reused Passwords (Vulnerable): {len(reused)}\n" + (", ".join(reused) if reused else "None! Perfect security.")
    
    messagebox.showinfo("Security Audit", msg)

# --- Export / Import / CSV ---
def export_vault():
    file_path = filedialog.asksaveasfilename(defaultextension=".vault", filetypes=[("Vault Backup", "*.vault")])
    if not file_path: return
    backup_pwd = simpledialog.askstring("Backup Password", "Create a password to lock this backup file:", show='*')
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
        except Exception: continue

    json_data = json.dumps(export_data).encode()
    salt = os.urandom(16)
    key = derive_key(backup_pwd, salt)
    f_cipher = Fernet(key)
    encrypted_payload = f_cipher.encrypt(json_data)

    with open(file_path, 'wb') as f: f.write(salt + encrypted_payload)
    messagebox.showinfo("Success", "Vault successfully backed up and heavily encrypted!")

def import_vault():
    file_path = filedialog.askopenfilename(filetypes=[("Vault Backup", "*.vault")])
    if not file_path: return
    backup_pwd = simpledialog.askstring("Backup Password", "Enter the password for this backup file:", show='*')
    if not backup_pwd: return

    try:
        with open(file_path, 'rb') as f: data = f.read()
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
        conn.commit(); conn.close(); load_passwords()
        messagebox.showinfo("Success", f"Imported {imported_count} passwords into your vault!")
    except Exception:
        messagebox.showerror("Error", "Failed to import! Incorrect password or corrupted file.")

def import_csv():
    file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if not file_path: return
    if not verify_master_password(): return

    try:
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            count = 0
            for row in reader:
                web = row.get('url') or row.get('name') or row.get('website')
                usr = row.get('username') or row.get('login')
                pwd = row.get('password')
                if web and pwd:
                    new_enc_pwd = cipher_suite.encrypt(pwd.encode()).decode()
                    cursor.execute("INSERT INTO credentials (website, username, password) VALUES (?, ?, ?)", (web, usr or "", new_enc_pwd))
                    count += 1
            conn.commit(); conn.close(); load_passwords()
            messagebox.showinfo("Success", f"Imported and encrypted {count} passwords from CSV!")
    except Exception:
        messagebox.showerror("Error", "Failed to read CSV. Ensure it has headers like 'url', 'username', and 'password'.")

# --- Language Dictionary ---
LANGUAGES = {
    "English": {
        "t1": "Generator & Save", "t2": "Saved Passwords", "t3": "Backup & Restore", "t4": "About",
        "web": "Website / App:", "usr": "Username / Email:", "len": "Password Length: ", "chars": "Characters Used:",
        "up": "Uppercase", "low": "Lowercase", "num": "Numbers", "sym": "Symbols",
        "btn_gen": "Generate Password", "btn_save": "Encrypt & Save",
        "btn_cpy": "Copy", "btn_shw": "Show", "btn_hid": "Hide",
        "search": "Search Vault:", "btn_audit": "Audit Health",
        "tree_web": "Website / App", "tree_usr": "Username / Email", "tree_pwd": "Password",
        "exp_title": "Export Encrypted Backup", "exp_desc": "Save a secure .vault file to your PC or a USB drive.", "btn_exp": "Export Vault...",
        "imp_title": "Import Backup (.vault)", "imp_desc": "Load an encrypted .vault file. Passwords will be instantly merged.", "btn_imp": "Import Vault...",
        "csv_title": "Import from CSV (Chrome / LastPass)", "csv_desc": "Select an unencrypted CSV file to instantly encrypt into your vault.", "btn_csv": "Import CSV...",
        "lang_lbl": "Display Language:"
    },
    "Turkish": {
        "t1": "Oluştur & Kaydet", "t2": "Kayıtlı Şifreler", "t3": "Yedekle & Yükle", "t4": "Hakkında",
        "web": "Web Sitesi / Uygulama:", "usr": "Kullanıcı Adı / E-posta:", "len": "Şifre Uzunluğu: ", "chars": "Kullanılan Karakterler:",
        "up": "Büyük Harf", "low": "Küçük Harf", "num": "Rakam", "sym": "Sembol",
        "btn_gen": "Şifre Oluştur", "btn_save": "Şifrele ve Kaydet",
        "btn_cpy": "Kopyala", "btn_shw": "Göster", "btn_hid": "Gizle",
        "search": "Kasada Ara:", "btn_audit": "Güvenlik Denetimi",
        "tree_web": "Web Sitesi / Uygulama", "tree_usr": "Kullanıcı Adı / E-posta", "tree_pwd": "Şifre",
        "exp_title": "Şifreli Yedek Dışa Aktar", "exp_desc": "Bilgisayarınıza veya USB belleğe güvenli bir .vault dosyası kaydedin.", "btn_exp": "Kasayı Dışa Aktar...",
        "imp_title": "Yedek İçe Aktar (.vault)", "imp_desc": "Şifrelenmiş bir .vault dosyası yükleyin. Şifreler anında birleştirilecektir.", "btn_imp": "Kasayı İçe Aktar...",
        "csv_title": "CSV'den İçe Aktar (Chrome / LastPass)", "csv_desc": "Kasanıza anında şifrelemek için şifrelenmemiş bir CSV dosyası seçin.", "btn_csv": "CSV İçe Aktar...",
        "lang_lbl": "Görüntüleme Dili:"
    },
    "Polish": {
        "t1": "Generator i Zapis", "t2": "Zapisane Hasła", "t3": "Kopia zapasowa", "t4": "O aplikacji",
        "web": "Strona / Aplikacja:", "usr": "Nazwa użytkownika / Email:", "len": "Długość hasła: ", "chars": "Użyte znaki:",
        "up": "Duże litery", "low": "Małe litery", "num": "Cyfry", "sym": "Symbole",
        "btn_gen": "Generuj Hasło", "btn_save": "Szyfruj i Zapisz",
        "btn_cpy": "Kopiuj", "btn_shw": "Pokaż", "btn_hid": "Ukryj",
        "search": "Przeszukaj sejf:", "btn_audit": "Audyt Bezpieczeństwa",
        "tree_web": "Strona / Aplikacja", "tree_usr": "Nazwa użytkownika / Email", "tree_pwd": "Hasło",
        "exp_title": "Eksportuj zaszyfrowaną kopię", "exp_desc": "Zapisz bezpieczny plik .vault na komputerze lub dysku USB.", "btn_exp": "Eksportuj sejf...",
        "imp_title": "Importuj kopię (.vault)", "imp_desc": "Wczytaj zaszyfrowany plik .vault. Hasła zostaną natychmiast scalone.", "btn_imp": "Importuj sejf...",
        "csv_title": "Importuj z CSV (Chrome/LastPass)", "csv_desc": "Wybierz niezaszyfrowany plik CSV, aby zaszyfrować go w swoim sejfie.", "btn_csv": "Importuj CSV...",
        "lang_lbl": "Język aplikacji:"
    },
    "Spanish": {
        "t1": "Generador", "t2": "Contraseñas", "t3": "Respaldo", "t4": "Acerca de",
        "web": "Sitio / App:", "usr": "Usuario / Correo:", "len": "Longitud: ", "chars": "Caracteres:",
        "up": "Mayúsculas", "low": "Minúsculas", "num": "Números", "sym": "Símbolos",
        "btn_gen": "Generar", "btn_save": "Encriptar y Guardar",
        "btn_cpy": "Copiar", "btn_shw": "Mostrar", "btn_hid": "Ocultar",
        "search": "Buscar:", "btn_audit": "Auditoría de Salud",
        "tree_web": "Sitio / App", "tree_usr": "Usuario / Correo", "tree_pwd": "Contraseña",
        "exp_title": "Exportar Respaldo", "exp_desc": "Guardar archivo .vault seguro.", "btn_exp": "Exportar...",
        "imp_title": "Importar Respaldo", "imp_desc": "Cargar archivo .vault.", "btn_imp": "Importar...",
        "csv_title": "Importar CSV", "csv_desc": "Importar CSV sin encriptar.", "btn_csv": "Importar CSV...",
        "lang_lbl": "Idioma:"
    },
    "Italian": {
        "t1": "Generatore", "t2": "Password", "t3": "Backup", "t4": "Info",
        "web": "Sito / App:", "usr": "Utente / Email:", "len": "Lunghezza: ", "chars": "Caratteri:",
        "up": "Maiuscole", "low": "Minuscole", "num": "Numeri", "sym": "Simboli",
        "btn_gen": "Genera", "btn_save": "Crittografa e Salva",
        "btn_cpy": "Copia", "btn_shw": "Mostra", "btn_hid": "Nascondi",
        "search": "Cerca:", "btn_audit": "Verifica Sicurezza",
        "tree_web": "Sito / App", "tree_usr": "Utente / Email", "tree_pwd": "Password",
        "exp_title": "Esporta Backup", "exp_desc": "Salva file .vault sicuro.", "btn_exp": "Esporta...",
        "imp_title": "Importa Backup", "imp_desc": "Carica file .vault.", "btn_imp": "Importa...",
        "csv_title": "Importa CSV", "csv_desc": "Importa CSV non crittografato.", "btn_csv": "Importa CSV...",
        "lang_lbl": "Lingua:"
    },
    "Portuguese": {
        "t1": "Gerador", "t2": "Senhas", "t3": "Backup", "t4": "Sobre",
        "web": "Site / App:", "usr": "Usuário / Email:", "len": "Tamanho: ", "chars": "Caracteres:",
        "up": "Maiúsculas", "low": "Minúsculas", "num": "Números", "sym": "Símbolos",
        "btn_gen": "Gerar", "btn_save": "Criptografar e Salvar",
        "btn_cpy": "Copiar", "btn_shw": "Mostrar", "btn_hid": "Ocultar",
        "search": "Buscar:", "btn_audit": "Auditoria de Segurança",
        "tree_web": "Site / App", "tree_usr": "Usuário / Email", "tree_pwd": "Senha",
        "exp_title": "Exportar Backup", "exp_desc": "Salvar arquivo .vault seguro.", "btn_exp": "Exportar...",
        "imp_title": "Importar Backup", "imp_desc": "Carregar arquivo .vault.", "btn_imp": "Importar...",
        "csv_title": "Importar CSV", "csv_desc": "Importar CSV não criptografado.", "btn_csv": "Importar CSV...",
        "lang_lbl": "Idioma:"
    }
}

def change_language(*args):
    lang = lang_var.get()
    save_config(lang) 
    trans = LANGUAGES.get(lang, LANGUAGES["English"])
    
    # Tabs
    notebook.tab(0, text=trans["t1"]); notebook.tab(1, text=trans["t2"])
    notebook.tab(2, text=trans["t3"]); notebook.tab(3, text=trans["t4"])
    
    # Generator Tab
    lbl_website.config(text=trans["web"])
    lbl_username.config(text=trans["usr"])
    lbl_length.config(text=f"{trans['len']}{length_var.get()}")
    lbl_chars.config(text=trans["chars"])
    chk_upper.config(text=trans["up"])
    chk_lower.config(text=trans["low"])
    chk_num.config(text=trans["num"])
    chk_sym.config(text=trans["sym"])
    generate_btn.config(text=trans["btn_gen"])
    save_btn.config(text=trans["btn_save"])
    btn_copy_gen.config(text=trans["btn_cpy"])
    
    if password_display.cget("show") == "*":
        btn_show_gen.config(text=trans["btn_shw"])
    else:
        btn_show_gen.config(text=trans["btn_hid"])

    # Vault Tab
    lbl_search.config(text=trans["search"])
    btn_audit.config(text=trans.get("btn_audit", "Audit Health"))
    tree.heading("Website", text=trans["tree_web"])
    tree.heading("Username", text=trans["tree_usr"])
    tree.heading("Password", text=trans["tree_pwd"])

    # Sync Tab
    lbl_exp_title.config(text=trans["exp_title"])
    lbl_exp_desc.config(text=trans["exp_desc"])
    btn_export.config(text=trans["btn_exp"])
    lbl_imp_title.config(text=trans["imp_title"])
    lbl_imp_desc.config(text=trans["imp_desc"])
    btn_import.config(text=trans["btn_imp"])
    lbl_csv_title.config(text=trans["csv_title"])
    lbl_csv_desc.config(text=trans["csv_desc"])
    btn_csv.config(text=trans["btn_csv"])

    # About Tab
    lbl_lang.config(text=trans["lang_lbl"])

# --- UI Setup & Startup Flow ---
root = tk.Tk()
root.withdraw() 
if not authenticate(): sys.exit() 
root.deiconify() 
root.title("Local Password Manager v1.6") 
root.geometry("650x520")

root.bind("<Any-KeyPress>", reset_lock_timer)
root.bind("<Any-Button>", reset_lock_timer)
reset_lock_timer()

init_db()
user_config = load_config()

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

# === TAB 1: GENERATOR ===
tab_generator.configure(padding=20)
length_var = tk.IntVar(value=16)
upper_var, lower_var, num_var, sym_var = tk.BooleanVar(value=True), tk.BooleanVar(value=True), tk.BooleanVar(value=True), tk.BooleanVar(value=True)

length_var.trace("w", update_strength)
upper_var.trace("w", update_strength); lower_var.trace("w", update_strength)
num_var.trace("w", update_strength); sym_var.trace("w", update_strength)

lbl_website = ttk.Label(tab_generator, text="Website / App:", font=("Arial", 10, "bold"))
lbl_website.grid(row=0, column=0, sticky="w", pady=(0, 5))
website_entry = ttk.Entry(tab_generator, width=30)
website_entry.grid(row=0, column=1, columnspan=4, sticky="w", pady=(0, 5))

lbl_username = ttk.Label(tab_generator, text="Username / Email:", font=("Arial", 10, "bold"))
lbl_username.grid(row=1, column=0, sticky="w", pady=(0, 15))
username_entry = ttk.Entry(tab_generator, width=30)
username_entry.grid(row=1, column=1, columnspan=4, sticky="w", pady=(0, 15))

ttk.Separator(tab_generator, orient='horizontal').grid(row=2, column=0, columnspan=5, sticky="ew", pady=10)

lbl_length = ttk.Label(tab_generator, text=f"Password Length: {length_var.get()}", font=("Arial", 10, "bold"))
lbl_length.grid(row=3, column=0, sticky="w", pady=(0, 10))
length_slider = ttk.Scale(tab_generator, from_=8, to_=64, orient="horizontal", variable=length_var)
length_slider.grid(row=3, column=1, columnspan=4, sticky="ew", pady=(0, 10))

lbl_chars = ttk.Label(tab_generator, text="Characters Used:", font=("Arial", 10, "bold"))
lbl_chars.grid(row=4, column=0, sticky="w", pady=10)
chk_upper = ttk.Checkbutton(tab_generator, text="Uppercase", variable=upper_var)
chk_upper.grid(row=4, column=1, sticky="w")
chk_lower = ttk.Checkbutton(tab_generator, text="Lowercase", variable=lower_var)
chk_lower.grid(row=4, column=2, sticky="w")
chk_num = ttk.Checkbutton(tab_generator, text="Numbers", variable=num_var)
chk_num.grid(row=4, column=3, sticky="w")
chk_sym = ttk.Checkbutton(tab_generator, text="Symbols", variable=sym_var)
chk_sym.grid(row=4, column=4, sticky="w")

strength_lbl = ttk.Label(tab_generator, text="Strength: Strong", font=("Arial", 9, "bold"), foreground="green")
strength_lbl.grid(row=5, column=0, sticky="w", pady=(10, 0))
strength_bar = ttk.Progressbar(tab_generator, orient="horizontal", mode="determinate", value=100)
strength_bar.grid(row=5, column=1, columnspan=4, sticky="ew", pady=(10, 0))

generate_btn = ttk.Button(tab_generator, text="Generate Password", command=generate_password)
generate_btn.grid(row=6, column=0, columnspan=5, pady=(15, 5))

gen_action_frame = ttk.Frame(tab_generator)
gen_action_frame.grid(row=7, column=0, columnspan=5, sticky="ew", pady=(0, 15))
password_display = ttk.Entry(gen_action_frame, font=("Courier", 12), justify="center", state="readonly", show="*")
password_display.pack(side="left", fill="x", expand=True, padx=(0, 5))
btn_copy_gen = ttk.Button(gen_action_frame, text="Copy", command=lambda: copy_to_clipboard(password_display.get(), btn_copy_gen) if password_display.get() else None)
btn_copy_gen.pack(side="left", padx=(0, 5))
btn_show_gen = ttk.Button(gen_action_frame, text="Show", command=toggle_gen_view)
btn_show_gen.pack(side="left")

lbl_notes = ttk.Label(tab_generator, text="Secure Notes:", font=("Arial", 10, "bold"))
lbl_notes.grid(row=8, column=0, sticky="nw", pady=(10, 0))
notes_entry = tk.Text(tab_generator, height=3, width=30, font=("Arial", 10))
notes_entry.grid(row=8, column=1, columnspan=4, sticky="ew", pady=(10, 0))

save_btn = ttk.Button(tab_generator, text="Encrypt & Save", command=save_password)
save_btn.grid(row=9, column=0, columnspan=5, pady=(15, 5)) # Changed to row 9
for i in range(1, 5): tab_generator.columnconfigure(i, weight=1)

# === TAB 2: VAULT ===
search_frame = ttk.Frame(tab_vault)
search_frame.pack(fill="x", padx=10, pady=10)
lbl_search = ttk.Label(search_frame, text="Search Vault:")
lbl_search.pack(side="left")
search_var = tk.StringVar()
search_var.trace("w", load_passwords) 
search_entry = ttk.Entry(search_frame, textvariable=search_var)
search_entry.pack(side="left", fill="x", expand=True, padx=10)

btn_audit = ttk.Button(search_frame, text="Audit Health", command=audit_vault)
btn_audit.pack(side="right", padx=10)

tree_frame = ttk.Frame(tab_vault)
tree_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
tree_scroll = ttk.Scrollbar(tree_frame)
tree_scroll.pack(side="right", fill="y")

columns = ("ID", "Website", "Username", "Password")
tree = ttk.Treeview(tree_frame, columns=columns, show="headings", yscrollcommand=tree_scroll.set)
tree.heading("ID", text="ID"); tree.heading("Website", text="Website / App"); tree.heading("Username", text="Username / Email"); tree.heading("Password", text="Password")
tree.column("ID", width=0, stretch=tk.NO); tree.column("Website", width=150); tree.column("Username", width=200); tree.column("Password", width=200)
tree.pack(side="left", fill="both", expand=True)
tree_scroll.config(command=tree.yview)

menu = tk.Menu(root, tearoff=0)
menu.add_command(label="Edit Entry", command=edit_password)
menu.add_command(label="Delete Entry", command=delete_password)
tree.bind("<Button-3>", popup_menu)
tree.bind("<Double-1>", view_password_details) 
load_passwords()

# === TAB 3: BACKUP & RESTORE ===
tab_sync.configure(padding=40)
lbl_exp_title = ttk.Label(tab_sync, text="Export Encrypted Backup", font=("Arial", 12, "bold"))
lbl_exp_title.pack(anchor="w", pady=(0, 5))
lbl_exp_desc = ttk.Label(tab_sync, text="Save a secure .vault file to your PC or a USB drive.", font=("Arial", 10))
lbl_exp_desc.pack(anchor="w", pady=(0, 10))
btn_export = ttk.Button(tab_sync, text="Export Vault...", command=export_vault)
btn_export.pack(anchor="w", pady=(0, 20))

lbl_imp_title = ttk.Label(tab_sync, text="Import Backup (.vault)", font=("Arial", 12, "bold"))
lbl_imp_title.pack(anchor="w", pady=(0, 5))
lbl_imp_desc = ttk.Label(tab_sync, text="Load an encrypted .vault file. Passwords will be instantly merged.", font=("Arial", 10))
lbl_imp_desc.pack(anchor="w", pady=(0, 10))
btn_import = ttk.Button(tab_sync, text="Import Vault...", command=import_vault)
btn_import.pack(anchor="w", pady=(0, 20))

lbl_csv_title = ttk.Label(tab_sync, text="Import from CSV (Chrome / LastPass)", font=("Arial", 12, "bold"))
lbl_csv_title.pack(anchor="w", pady=(0, 5))
lbl_csv_desc = ttk.Label(tab_sync, text="Select an unencrypted CSV file to instantly encrypt into your vault.", font=("Arial", 10))
lbl_csv_desc.pack(anchor="w", pady=(0, 10))
btn_csv = ttk.Button(tab_sync, text="Import CSV...", command=import_csv)
btn_csv.pack(anchor="w")

# === TAB 4: ABOUT & SETTINGS ===
tab_about.configure(padding=40)
ttk.Label(tab_about, text="Local Password Manager", font=("Arial", 16, "bold")).pack(pady=(10, 5))
ttk.Label(tab_about, text="Version 1.6", font=("Arial", 10)).pack(pady=(0, 20))

lbl_lang = ttk.Label(tab_about, text="Display Language:", font=("Arial", 10, "bold"))
lbl_lang.pack(pady=(10, 2))
lang_var = tk.StringVar(value=user_config.get("language", "English"))
lang_dropdown = ttk.Combobox(tab_about, textvariable=lang_var, values=list(LANGUAGES.keys()), state="readonly")
lang_dropdown.pack(pady=(0, 20))
lang_dropdown.bind("<<ComboboxSelected>>", change_language)

ttk.Label(tab_about, text="100% Free and Open-Source.", font=("Arial", 10, "italic")).pack(pady=(0, 20))
ttk.Label(tab_about, text="Created by Mustafa", font=("Arial", 11, "bold")).pack(pady=(10, 5))

# Initialize language on startup
change_language()

root.mainloop()