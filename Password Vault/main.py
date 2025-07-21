import os
import json
import base64
import datetime
import csv
import pyperclip
import qrcode
from PIL import Image, ImageTk
from zxcvbn import zxcvbn
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, simpledialog, filedialog
from tooltip import create_tooltip
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend

CONFIG_FILE = 'config.json'
VAULT_FILE = 'vault.json'
SALT_SIZE = 16
ITERATIONS = 390000
BACKUP_DIR = 'backups'
AUTOLOCK_SECONDS = 180
ICON_PATH = 'icon.ico'
LOGO_PATH = 'logo.png'

def generate_salt():
    return base64.urlsafe_b64encode(os.urandom(SALT_SIZE)).decode()

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.urlsafe_b64decode(salt.encode()),
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.urlsafe_b64decode(salt.encode()),
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()

def config_exists():
    return os.path.exists(CONFIG_FILE)

def save_config(hashed_pw, salt):
    with open(CONFIG_FILE, 'w') as f:
        json.dump({'master': hashed_pw, 'salt': salt}, f)

def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def vault_exists():
    return os.path.exists(VAULT_FILE)

def encrypt_vault(data, key):
    f = Fernet(key)
    token = f.encrypt(json.dumps(data).encode())
    with open(VAULT_FILE, 'wb') as fobj:
        fobj.write(token)

def decrypt_vault(key):
    if not vault_exists():
        return []
    with open(VAULT_FILE, 'rb') as fobj:
        token = fobj.read()
    f = Fernet(key)
    try:
        data = f.decrypt(token)
        return json.loads(data.decode())
    except InvalidToken:
        return None

def save_vault(data, key):
    encrypt_vault(data, key)
    auto_backup()

def auto_backup():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    backup_name = f'vault_backup_{datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.json'
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    with open(VAULT_FILE, 'rb') as src, open(backup_path, 'wb') as dst:
        dst.write(src.read())

class PasswordVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title('Password Vault')
        self.root.geometry('900x600')
        self.root.resizable(True, True)
        self.root.tk.call("tk", "scaling", 2.0)
        try:
            self.root.iconbitmap(ICON_PATH)
        except Exception:
            pass
        self.key = None
        self.vault = []
        self.show_passwords = False
        self.theme = 'cyborg'
        self.last_activity = datetime.datetime.now()
        self.categories = ['General', 'Social', 'Bank', 'Mail', 'Work', 'Other']
        self.style = ttk.Style(self.theme)
        self.show_login()
        self.start_autolock_timer()

    def show_login(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        frame = ttk.Frame(self.root, padding=30)
        frame.grid(row=0, column=0, sticky='nsew')
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        if os.path.exists(LOGO_PATH):
            img = Image.open(LOGO_PATH).resize((80, 80))
            img_tk = ImageTk.PhotoImage(img)
            logo_label = ttk.Label(frame, image=img_tk)
            logo_label.image = img_tk
            logo_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        ttk.Label(frame, text='Master Password:', font=('Segoe UI', 18, 'bold')).grid(row=1, column=0, pady=10, padx=5, sticky='e')
        pw_entry = ttk.Entry(frame, show='*', font=('Segoe UI', 18), width=20)
        pw_entry.grid(row=1, column=1, pady=10, padx=5, sticky='w')
        pw_entry.focus()
        create_tooltip(pw_entry, "Enter your master password or set it for the first use.")
        def on_submit():
            password = pw_entry.get()
            if not config_exists():
                if len(password) < 6:
                    messagebox.showerror('Error', 'Password must be at least 6 characters!')
                    return
                salt = generate_salt()
                hashed = hash_password(password, salt)
                save_config(hashed, salt)
                self.key = derive_key(password, salt)
                self.vault = []
                save_vault(self.vault, self.key)
                messagebox.showinfo('Success', 'Master password set!')
                self.show_main()
            else:
                conf = load_config()
                hashed = hash_password(password, conf['salt'])
                if hashed != conf['master']:
                    messagebox.showerror('Wrong Password', 'Master password is incorrect!')
                    return
                self.key = derive_key(password, conf['salt'])
                vault = decrypt_vault(self.key)
                if vault is None:
                    messagebox.showerror('Error', 'Vault file could not be opened. Wrong password or file is corrupted.')
                    return
                self.vault = vault
                self.show_main()
        login_btn = ttk.Button(frame, text='Login', command=on_submit, bootstyle=SUCCESS, width=15)
        login_btn.grid(row=2, column=0, columnspan=2, pady=20)
        create_tooltip(login_btn, "Login or set master password.")

    def show_main(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.last_activity = datetime.datetime.now()
        self.root.grid_rowconfigure(0, weight=0)
        self.root.grid_rowconfigure(1, weight=0)
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.grid(row=0, column=0, sticky='ew')
        welcome = ttk.Label(top_frame, text="🔐 Welcome!", font=("Segoe UI", 18, "bold"))
        welcome.pack(side="left", padx=10)
        theme_btn = ttk.Button(top_frame, text="🌙 Switch Theme", command=self.toggle_theme, bootstyle=SECONDARY)
        theme_btn.pack(side='right', padx=5)
        create_tooltip(theme_btn, "Switch between light/dark mode.")
        logout_btn = ttk.Button(top_frame, text='Logout', command=self.show_login, bootstyle=DANGER)
        logout_btn.pack(side='right', padx=5)
        create_tooltip(logout_btn, "Logout.")
        mid_frame = ttk.Frame(self.root, padding=10)
        mid_frame.grid(row=1, column=0, sticky='ew')
        ttk.Label(mid_frame, text='Search:', font=('Segoe UI', 14)).pack(side='left', padx=5)
        self.search_var = ttk.StringVar()
        self.search_var.trace_add('write', self.filter_tree)
        search_entry = ttk.Entry(mid_frame, textvariable=self.search_var, width=30, font=('Segoe UI', 14))
        search_entry.pack(side='left', padx=5)
        create_tooltip(search_entry, "Filter by site, username or password.")
        self.show_pw_btn = ttk.Button(mid_frame, text='Show Passwords', command=self.toggle_passwords, bootstyle=INFO)
        self.show_pw_btn.pack(side='left', padx=5)
        create_tooltip(self.show_pw_btn, "Show/hide passwords.")
        ttk.Label(mid_frame, text='Category:', font=('Segoe UI', 14)).pack(side='left', padx=5)
        self.category_var = ttk.StringVar(value='All')
        cat_options = ['All'] + self.categories
        cat_menu = ttk.OptionMenu(mid_frame, self.category_var, 'All', *cat_options, command=lambda _: self.filter_tree())
        cat_menu.pack(side='left', padx=5)
        create_tooltip(cat_menu, "Filter by category.")
        add_btn = ttk.Button(mid_frame, text='Add New Password', command=self.add_entry, bootstyle=SUCCESS)
        add_btn.pack(side='left', padx=5)
        create_tooltip(add_btn, "Add a new password entry.")
        delall_btn = ttk.Button(mid_frame, text='Delete All', command=self.delete_all, bootstyle=WARNING)
        delall_btn.pack(side='left', padx=5)
        create_tooltip(delall_btn, "Delete all passwords.")
        export_btn = ttk.Button(mid_frame, text='Export', command=self.export_vault, bootstyle=PRIMARY)
        export_btn.pack(side='left', padx=5)
        create_tooltip(export_btn, "Export passwords (JSON/CSV).")
        import_btn = ttk.Button(mid_frame, text='Import', command=self.import_vault, bootstyle=PRIMARY)
        import_btn.pack(side='left', padx=5)
        create_tooltip(import_btn, "Import passwords (JSON/CSV).")
        backup_btn = ttk.Button(mid_frame, text='Restore Backup', command=self.restore_backup, bootstyle=PRIMARY)
        backup_btn.pack(side='left', padx=5)
        create_tooltip(backup_btn, "Restore from automatic backups.")
        table_frame = ttk.Frame(self.root, padding=10)
        table_frame.grid(row=2, column=0, sticky='nsew')
        self.root.grid_rowconfigure(2, weight=1)
        columns = ('site', 'username', 'password', 'category', 'copy', 'qr')
        self.tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=15, bootstyle=INFO)
        self.tree.heading('site', text='Site')
        self.tree.heading('username', text='Username')
        self.tree.heading('password', text='Password')
        self.tree.heading('category', text='Category')
        self.tree.heading('copy', text='')
        self.tree.heading('qr', text='')
        self.tree.column('site', width=180)
        self.tree.column('username', width=140)
        self.tree.column('password', width=120)
        self.tree.column('category', width=100)
        self.tree.column('copy', width=50, anchor='center')
        self.tree.column('qr', width=50, anchor='center')
        self.tree.grid(row=0, column=0, sticky='nsew')
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        self.tree.bind('<Button-1>', self.on_tree_click)
        self.refresh_tree()

    def refresh_tree(self, *_):
        for i in self.tree.get_children():
            self.tree.delete(i)
        filtered = self.get_filtered_vault()
        for idx, entry in enumerate(filtered):
            pw = entry['password'] if self.show_passwords else '●●●●●●●●'
            self.tree.insert('', 'end', iid=idx, values=(entry['site'], entry['username'], pw, entry.get('category', 'General'), '📋', '🔳'))

    def get_filtered_vault(self):
        q = self.search_var.get().lower()
        cat = self.category_var.get()
        filtered = []
        for entry in self.vault:
            if (q in entry['site'].lower() or q in entry['username'].lower() or q in entry['password'].lower()):
                if cat == 'All' or entry.get('category', 'General') == cat:
                    filtered.append(entry)
        return filtered

    def filter_tree(self, *args):
        self.refresh_tree()

    def add_entry(self):
        win = ttk.Toplevel(self.root)
        win.title('Add New Password')
        win.geometry('700x520')
        win.resizable(True, True)
        win.grab_set()
        win.update_idletasks()
        x = (win.winfo_screenwidth() // 2) - (700 // 2)
        y = (win.winfo_screenheight() // 2) - (520 // 2)
        win.geometry(f'+{x}+{y}')
        ttk.Label(win, text='Site:', font=('Segoe UI', 14)).pack(pady=5)
        site_entry = ttk.Entry(win, font=('Segoe UI', 14))
        site_entry.pack(pady=5)
        create_tooltip(site_entry, "Enter the site name.")
        ttk.Label(win, text='Username:', font=('Segoe UI', 14)).pack(pady=5)
        user_entry = ttk.Entry(win, font=('Segoe UI', 14))
        user_entry.pack(pady=5)
        create_tooltip(user_entry, "Enter the username.")
        ttk.Label(win, text='Password:', font=('Segoe UI', 14)).pack(pady=5)
        pw_entry = ttk.Entry(win, font=('Segoe UI', 14))
        pw_entry.pack(pady=5)
        create_tooltip(pw_entry, "Password to save.")
        strength_label = ttk.Label(win, text='')
        strength_label.pack(pady=2)
        def on_pw_change(*args):
            pw = pw_entry.get()
            if not pw:
                strength_label.config(text='')
                return
            result = zxcvbn(pw)
            score = result['score']
            txt = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'][score]
            color = ['#d00', '#e55', '#fa0', '#5c5', '#0c0'][score]
            strength_label.config(text=f'Password Strength: {txt}', foreground=color)
        pw_entry.bind('<KeyRelease>', on_pw_change)
        ttk.Label(win, text='Category:', font=('Segoe UI', 14)).pack(pady=5)
        cat_var = ttk.StringVar(value=self.categories[0])
        cat_menu = ttk.OptionMenu(win, cat_var, self.categories[0], *self.categories)
        cat_menu.pack(pady=5)
        create_tooltip(cat_menu, "Select password category.")
        def on_add():
            site = site_entry.get().strip()
            user = user_entry.get().strip()
            pw = pw_entry.get().strip()
            cat = cat_var.get()
            if not site or not user or not pw:
                messagebox.showerror('Error', 'All fields are required!')
                return
            self.vault.append({'site': site, 'username': user, 'password': pw, 'category': cat})
            save_vault(self.vault, self.key)
            self.refresh_tree()
            win.destroy()
        save_btn = ttk.Button(win, text='Save', command=on_add, bootstyle=SUCCESS, width=20)
        save_btn.pack(pady=20)
        create_tooltip(save_btn, "Save the password to the vault.")

    def on_tree_click(self, event):
        region = self.tree.identify('region', event.x, event.y)
        if region != 'cell':
            return
        col = self.tree.identify_column(event.x)
        row = self.tree.identify_row(event.y)
        if not row:
            return
        idx = int(row)
        filtered = self.get_filtered_vault()
        if idx >= len(filtered):
            return
        if col == '#5':
            pw = filtered[idx]['password']
            pyperclip.copy(pw)
            messagebox.showinfo('Copied', 'Password copied to clipboard!')
        elif col == '#6':
            pw = filtered[idx]['password']
            qr = qrcode.make(pw)
            win = ttk.Toplevel(self.root)
            win.title('QR Code')
            win.geometry('300x320')
            img = qr.resize((250, 250))
            img_tk = ImageTk.PhotoImage(img)
            label = ttk.Label(win, image=img_tk)
            label.image = img_tk
            label.pack(pady=10)
            ttk.Label(win, text='You can share the password via QR code.').pack(pady=5)

    def delete_all(self):
        if messagebox.askyesno('Delete All', 'Are you sure you want to delete all passwords?'):
            self.vault = []
            save_vault(self.vault, self.key)
            self.refresh_tree()

    def toggle_passwords(self):
        self.show_passwords = not self.show_passwords
        self.show_pw_btn.config(text='Hide Passwords' if self.show_passwords else 'Show Passwords')
        self.refresh_tree()

    def toggle_theme(self):
        self.theme = 'flatly' if self.theme == 'cyborg' else 'cyborg'
        self.style = ttk.Style(self.theme)
        self.show_main()

    def export_vault(self):
        filetypes = [('JSON', '*.json'), ('CSV', '*.csv')]
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=filetypes)
        if not path:
            return
        if path.endswith('.json'):
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.vault, f, ensure_ascii=False, indent=2)
        elif path.endswith('.csv'):
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['site', 'username', 'password', 'category'])
                writer.writeheader()
                for row in self.vault:
                    writer.writerow(row)
        messagebox.showinfo('Success', 'Passwords exported!')

    def import_vault(self):
        filetypes = [('JSON', '*.json'), ('CSV', '*.csv')]
        path = filedialog.askopenfilename(filetypes=filetypes)
        if not path:
            return
        imported = []
        try:
            if path.endswith('.json'):
                with open(path, 'r', encoding='utf-8') as f:
                    imported = json.load(f)
            elif path.endswith('.csv'):
                with open(path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    imported = list(reader)
            for row in imported:
                if not all(k in row for k in ['site', 'username', 'password', 'category']):
                    raise ValueError('Missing field!')
            self.vault.extend(imported)
            save_vault(self.vault, self.key)
            self.refresh_tree()
            messagebox.showinfo('Success', 'Passwords imported!')
        except Exception as e:
            messagebox.showerror('Error', f'Import failed: {e}')

    def restore_backup(self):
        if not os.path.exists(BACKUP_DIR):
            messagebox.showerror('Error', 'No backup found!')
            return
        files = [f for f in os.listdir(BACKUP_DIR) if f.startswith('vault_backup_') and f.endswith('.json')]
        if not files:
            messagebox.showerror('Error', 'No backup found!')
            return
        win = ttk.Toplevel(self.root)
        win.title('Restore Backup')
        win.geometry('400x300')
        lb = ttk.Listbox(win, font=('Segoe UI', 12))
        for f in sorted(files, reverse=True):
            lb.insert('end', f)
        lb.pack(fill='both', expand=True, padx=10, pady=10)
        def on_load():
            sel = lb.curselection()
            if not sel:
                return
            fname = files[sel[0]]
            with open(os.path.join(BACKUP_DIR, fname), 'rb') as fsrc, open(VAULT_FILE, 'wb') as fdst:
                fdst.write(fsrc.read())
            self.vault = decrypt_vault(self.key)
            self.refresh_tree()
            win.destroy()
            messagebox.showinfo('Success', 'Backup restored!')
        load_btn = ttk.Button(win, text='Restore Selected', command=on_load, bootstyle=SUCCESS)
        load_btn.pack(pady=5)
        create_tooltip(load_btn, "Restore the selected backup.")

    def start_autolock_timer(self):
        def check():
            if (datetime.datetime.now() - self.last_activity).total_seconds() > AUTOLOCK_SECONDS:
                self.show_login()
            else:
                self.root.after(1000, check)
        self.root.after(1000, check)

if __name__ == '__main__':
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(u'passwordvault')
    except Exception:
        pass
    root = ttk.Window(themename="cyborg")
    app = PasswordVaultApp(root)
    root.mainloop() 