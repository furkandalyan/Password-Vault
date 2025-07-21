# Password Vault

A modern, secure, and user-friendly password manager with AES-256 encryption and a beautiful GUI.

## Features

- **Master Password Login**: Set and use a single master password to access your vault.
- **AES-256 Encryption**: All passwords are encrypted using Fernet (AES-256) and stored securely.
- **Add, View, Delete Passwords**: Manage your credentials for any site or service.
- **Search & Filter**: Instantly search and filter your passwords by site, username, or category.
- **Copy to Clipboard**: Copy passwords with a single click.
- **Show/Hide Passwords**: Toggle password visibility in the list.
- **Password Strength Meter**: See the strength of new passwords as you type.
- **Categories/Tags**: Organize passwords by category (e.g., Social, Bank, Work).
- **Export/Import**: Export or import your vault as JSON or CSV.
- **Automatic Backups**: Daily backups with easy restore.
- **QR Code Sharing**: Share passwords via QR code.
- **Dark/Light Theme**: Switch between modern dark and light themes.
- **Responsive & 4K Ready**: Scales beautifully on all screens.
- **Tooltips**: Helpful tooltips for every button and field.
- **Custom Icon & Logo**: Add your own branding.
- **Auto-Lock**: Vault locks automatically after inactivity.

## Screenshots

> _Add screenshots of the login screen, main vault, add password dialog, and dark mode here._

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repo-url>
   cd Password Vault
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **(Optional) Add your icon/logo:**
   - Place your `icon.ico` and `logo.png` in the project root for custom branding.

## Usage

Run the application:
```bash
python main.py
```

- On first launch, set your master password.
- Add, view, and manage your passwords securely.
- Use the top menu to switch theme, export/import, or restore backups.
- Double-click the copy or QR code icons to copy/share passwords.

## Security
- All data is encrypted with AES-256 (Fernet) using a key derived from your master password and a unique salt.
- The master password hash and salt are stored in `config.json`.
- The encrypted vault is stored in `vault.json`.
- Backups are stored in the `backups/` folder.

## Dependencies
- Python 3.8+
- cryptography
- pyperclip
- pillow
- qrcode
- zxcvbn
- ttkbootstrap

Install all dependencies with:
```bash
pip install -r requirements.txt
```

## License

MIT License

---

**Enjoy your secure and beautiful password vault!**
