# MobApp DataExtractor

> A tool for listing and extracting installed Android APKs and decrypted iOS IPAs (plus app storage) from rooted or jailbroken devices.

<img width="825" alt="image" src="https://github.com/user-attachments/assets/b52f607b-203a-42a5-9b53-f3c5f404225b" />


## ⚠️ Important Notes

* **Root / Jailbreak** is mandatory. Without it, data-pull commands will fail.
* Default SSH password is **`alpine`**. If you’ve changed it, update the `SSH_PASSWORD` variable or your scripts accordingly.

---

## ⚙️ Prerequisites

### Android

* Device **must be rooted** (or running in an emulator with root).
* `adb` installed and on your `PATH`.
* USB Debugging **enabled** on the device.

### iOS

* Device **must be jailbroken**.
* `libimobiledevice` installed (provides `iproxy`, `idevice_id`, etc.).
* SSH server (OpenSSH) installed and running on the device.

  ```bash
  # Default credentials:
  username: root
  password: alpine
  ```

### Host Machine

* Python **3.8+**
* Git
* Clone this repo and install Python dependencies:

  ```bash
  git clone https://github.com/yourusername/MobApp-Data-Extractor.git
  cd MobApp-Data-Extractor
  pip3 install --user -r requirements.txt
  ```

---

## 🐧 Linux & macOS Setup

Install the required system packages and tools:

```bash
# Install Python dependencies
pip3 install --user -r requirements.txt

# Debian/Ubuntu/Kali:
sudo apt update
sudo apt install iproxy
sudo apt install adb



# macOS (Homebrew):
brew update
brew install android-platform-tools libimobiledevice
```

> This installs `adb` and `iproxy` (from `libimobiledevice`).

---

## 🔧 SSH Setup on iOS

1. **Palera1n Initial Install**
   When installing via Palera1n, set the root password to **`alpine`** on first boot.

2. **Install OpenSSH & NewTerm**
   Open **Sileo**, search for and install **`OpenSSH`** and **`NewTerm`**.

3. **Configure via NewTerm**

   ```bash
   sudo su
   alpine
   ```

---

## 🛠️ Usage

```bash
# Android:
python3 MobApp-Data-Extractor.py android list-all
python3 MobApp-Data-Extractor.py android list-user
python3 MobApp-Data-Extractor.py android get-apk <package_name>
python3 MobApp-Data-Extractor.py android get-data <package_name>

# iOS:
python3 MobApp-Data-Extractor.py ios list-all
python3 MobApp-Data-Extractor.py ios get-ipa <package_name>
python3 MobApp-Data-Extractor.py ios get-data <package_name>
```

---

## 🗂️ Output Structure

All extracted files are stored under `output/`:

```
output/
├─ Android/
│  ├─ apks/
│  │  └─ <package_name>/
│  └─ data/
│     └─ <package_name>/
└─ ios/
   ├─ ipas/
   │  └─ <bundle_id>/
   └─ data/
      └─ <bundle_id>/
```

---

## 🧰 Scripts

* **Core Script**:

  * `MobApp-Data-Extractor.py` – Main extraction utility.

* **Dependencies**:

  * `requirements.txt` – Python package requirements.

* **JavaScript Dump Helpers** (via Frida):

  * `app-dumper.js` – Dump APK contents in memory.
  * `storage-locator.js` – Locate app storage paths.
  * `localstorage.js` – Pull SQLite, SharedPreferences, IndexedDB.
  * `dump.js` – Generic Frida-based dump utilities.

  *Thanks to [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) by AloneMonkey for the unencrypted IPA script.*
