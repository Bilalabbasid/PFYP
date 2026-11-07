# PhishGuard — Phishing Link Detection & Cybersecurity Awareness System

PhishGuard is a Flask web application that analyses a link and tells you whether it looks
**Likely Safe**, **Suspicious** or **Likely Phishing** — with every reason explained in plain
language. It also keeps a scan history, teaches users to recognise phishing (guides + quiz) and
gives administrators a monitoring dashboard.

> The submitted link is **never opened**: only the text of the URL is analysed. The system never
> asks for passwords or banking details.

**Contents**
1. [Run it locally (quick setup)](#1-run-it-locally-quick-setup)
2. [Run it locally (manual, step by step)](#2-run-it-locally-manual-step-by-step)
3. [Using the app](#3-using-the-app)
4. [Configuration (.env)](#4-configuration-env)
5. [Using MySQL](#5-using-mysql)
6. [Deployment](#6-deployment)
7. [Tests and evaluation](#7-tests-and-evaluation)
8. [How detection works](#8-how-detection-works)
9. [Project structure, API, security](#9-project-structure-api-security)
10. [Troubleshooting](#10-troubleshooting)

---

## Requirements

- **Python 3.11 or newer**: <https://www.python.org/downloads/>
  (on Windows tick **"Add python.exe to PATH"** in the installer)
- **Git**: <https://git-scm.com/downloads>
- Optional: **MySQL 8** or **Docker**. Not needed to run locally; SQLite is used by default.

Check what you have:

```bash
python --version
```
```bash
git --version
```

---

## 1. Run it locally (quick setup)

**Step 1: Download the code**

```bash
git clone https://github.com/Bilalabbasid/PFYP.git
```
```bash
cd PFYP
```

**Step 2: Run the setup script once.** It creates a virtual environment, installs the
dependencies, creates `.env`, trains the ML model, and creates the database with demo accounts.

Windows (Command Prompt or PowerShell):

```bash
setup.bat
```

macOS / Linux:

```bash
sh setup.sh
```

The first run downloads about 100 MB of packages and can take a few minutes.

**Step 3: Start the app**

Windows:

```bash
run.bat
```

macOS / Linux:

```bash
.venv/bin/python run.py
```

**Step 4:** Open <http://127.0.0.1:5000> in your browser. Press `Ctrl + C` in the terminal to stop.

---

## 2. Run it locally (manual, step by step)

Use this if you prefer to see each step, or if the setup script fails.
Run all commands from inside the project folder.

### Step 1: Clone the repository

```bash
git clone https://github.com/Bilalabbasid/PFYP.git
```
```bash
cd PFYP
```

### Step 2: Create a virtual environment

| Windows | macOS / Linux |
|---|---|
| `python -m venv .venv` | `python3 -m venv .venv` |

### Step 3: Activate it

| Windows (Command Prompt) | Windows (PowerShell) | macOS / Linux |
|---|---|---|
| `.venv\Scripts\activate.bat` | `.venv\Scripts\Activate.ps1` | `source .venv/bin/activate` |

Your prompt now starts with `(.venv)`. All commands below assume it is active.

> PowerShell says "running scripts is disabled"? Run
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use Command Prompt instead.

### Step 4: Install the dependencies

```bash
python -m pip install --upgrade pip
```
```bash
pip install -r requirements.txt
```

### Step 5: Create your configuration file

| Windows | macOS / Linux |
|---|---|
| `copy .env.example .env` | `cp .env.example .env` |

The defaults work as they are (SQLite database, ML enabled). See [section 4](#4-configuration-env).

### Step 6: (Optional) Train the machine-learning model

```bash
python ml/build_dataset.py
```
```bash
python ml/train_model.py
```

If you skip this, the app works with the rule-based engine only.

### Step 7: Create the database, demo accounts and sample data

```bash
flask --app run seed-demo
```

This creates `instance/phishguard.db` plus these **demo-only** accounts:

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin1234` |
| Normal user | `demo` | `Demo1234` |

To create your own administrator instead (you will be asked for the details):

```bash
flask --app run create-admin
```

### Step 8: Start the app

```bash
python run.py
```

Open <http://127.0.0.1:5000>. Press `Ctrl + C` to stop.

Next time you only need **Step 3 (activate)** and **Step 8 (run)**.

---

## 3. Using the app

| Page | What to do |
|---|---|
| **Scan** (home) | Paste a link such as `http://paypa1.com/signin` and press **Analyse**. You get a verdict, a risk score, the reasons, a "what to do now" checklist and a 5-question **message check** (expected? urgent? asks for OTP?…) that refines the advice. |
| **History** | Log in first. Search, filter, delete and export your scans to CSV. |
| **Learn** | 7 awareness guides and the **Spot the Phish** quiz (keys `L` = legitimate, `P` = phishing). |
| **How it works** | Detection workflow and the list of security checks. |
| **Admin** | Log in as `admin`. Dashboard and charts, users, all scanned URLs, awareness content editor, activity log. |

Public sign-up never creates administrators; use `flask --app run create-admin` or make a user
admin from the **Admin → Users** page.

---

## 4. Configuration (.env)

`run.py` reads `.env` automatically. All settings are optional.

| Setting | Default | Meaning |
|---|---|---|
| `SECRET_KEY` | generated and saved in `instance/secret_key` | Signs sessions. **Set a long random value in production.** |
| `DATABASE_URL` | SQLite file `instance/phishguard.db` | e.g. `mysql+pymysql://user:pass@host:3306/phishguard` |
| `ML_ENABLED` | `1` | Use `ml/model.joblib` when it exists |
| `SESSION_COOKIE_SECURE` | `0` | Set `1` when the site is served over HTTPS |
| `BEHIND_PROXY` | `0` | Set `1` behind nginx, Docker or a hosting platform |
| `MAX_FAILED_LOGINS` / `LOCKOUT_MINUTES` | `5` / `10` | Account lock-out policy |
| `HOST` / `PORT` / `FLASK_DEBUG` | `127.0.0.1` / `5000` / `0` | Development server only |

Generate a secret key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## 5. Using MySQL

SQLite needs no setup. To use MySQL instead:

**Step 1: Get a MySQL 8 server.** Install it yourself, or start the included Docker container:

```bash
docker compose up -d mysql
```

If you use your own server, create the database and user:

```sql
CREATE DATABASE phishguard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'phishguard'@'localhost' IDENTIFIED BY 'choose-a-password';
GRANT ALL PRIVILEGES ON phishguard.* TO 'phishguard'@'localhost';
FLUSH PRIVILEGES;
```

**Step 2: Point the app at it** in `.env`. This is the Docker container's development password:

```
DATABASE_URL=mysql+pymysql://phishguard:phishguard_dev@127.0.0.1:3306/phishguard
```

**Step 3: Create the tables with the migrations**

```bash
flask --app run db upgrade
```

**Step 4: Optionally add demo data, then run as usual**

```bash
flask --app run seed-demo
```
```bash
python run.py
```

Prefer plain SQL? `database/mysql_migrations.sql` contains the same schema:
`mysql -u root -p < database/mysql_migrations.sql`.

### Changing the database schema later

1. Edit `app/models.py`.
2. Generate a migration: `flask --app run db migrate -m "what changed"`
3. Check the new file in `migrations/versions/`.
4. Apply it: `flask --app run db upgrade` (on every environment, before starting the new code).

`tests/test_migrations.py` fails if the models change without a migration.

---

## 6. Deployment

Pick **one** option. Every option needs these production settings:

- [ ] a long random `SECRET_KEY`
- [ ] `FLASK_DEBUG=0` (default)
- [ ] HTTPS, with `SESSION_COOKIE_SECURE=1`
- [ ] `BEHIND_PROXY=1` when behind nginx / a platform proxy
- [ ] your own admin from `flask --app run create-admin`. **Do not run `seed-demo` in production.**
- [ ] a production server (gunicorn / waitress), never `python run.py`

### Option A: Linux server (Ubuntu 22.04/24.04) with MySQL, gunicorn, nginx and HTTPS

**Step 1: Install the system packages**

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git nginx mysql-server
```

**Step 2: Create the MySQL database and user**

```bash
sudo mysql
```

Run the SQL from [section 5, step 1](#5-using-mysql) with a strong password, then type `exit`.

**Step 3: Get the code and install it**

```bash
sudo mkdir -p /opt/phishguard && sudo chown $USER /opt/phishguard
```
```bash
git clone https://github.com/Bilalabbasid/PFYP.git /opt/phishguard
```
```bash
cd /opt/phishguard && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

**Step 4: Configure** `/opt/phishguard/.env`:

```
SECRET_KEY=<output of: python3 -c "import secrets; print(secrets.token_hex(32))">
DATABASE_URL=mysql+pymysql://phishguard:<password>@localhost:3306/phishguard
SESSION_COOKIE_SECURE=1
BEHIND_PROXY=1
ML_ENABLED=1
```

**Step 5: Create the tables, train the model and create the administrator**

```bash
.venv/bin/flask --app run db upgrade
```
```bash
.venv/bin/python ml/build_dataset.py && .venv/bin/python ml/train_model.py
```
```bash
.venv/bin/flask --app run create-admin
```

**Step 6: Run gunicorn as a service.** Create `/etc/systemd/system/phishguard.service`:

```ini
[Unit]
Description=PhishGuard
After=network.target mysql.service

[Service]
User=www-data
WorkingDirectory=/opt/phishguard
ExecStart=/opt/phishguard/.venv/bin/gunicorn --workers 3 --bind 127.0.0.1:8000 wsgi:app
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo chown -R www-data:www-data /opt/phishguard
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now phishguard
```

**Step 7: Put nginx in front.** Create `/etc/nginx/sites-available/phishguard`
and replace `your-domain.com` with your domain:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/phishguard /etc/nginx/sites-enabled/ && sudo nginx -t && sudo systemctl reload nginx
```

**Step 8: Enable HTTPS (free certificate)**

```bash
sudo apt install -y certbot python3-certbot-nginx && sudo certbot --nginx -d your-domain.com
```

**Updating later:**

```bash
cd /opt/phishguard && sudo -u www-data git pull && sudo -u www-data .venv/bin/pip install -r requirements.txt && sudo -u www-data .venv/bin/flask --app run db upgrade && sudo systemctl restart phishguard
```

### Option B: Docker (any machine with Docker)

The included `Dockerfile` and `docker-compose.yml` run the app and MySQL 8 together. The image
trains the ML model at build time and applies migrations on start.

**Step 1:** Next to `docker-compose.yml`, create a `.env` with your own values:

```
SECRET_KEY=<long random value>
MYSQL_PASSWORD=<strong password>
MYSQL_ROOT_PASSWORD=<another strong password>
```

**Step 2: Build and start**

```bash
docker compose up -d --build
```

**Step 3: Create your administrator**

```bash
docker compose exec web flask --app run create-admin
```

**Step 4:** Open <http://localhost:8000>. For a public server, put it behind nginx with HTTPS as in
Option A (steps 7–8, `proxy_pass http://127.0.0.1:8000`), and add `BEHIND_PROXY=1` and
`SESSION_COOKIE_SECURE=1` to `.env`.

Useful commands: `docker compose logs -f web`, `docker compose down` (data is kept in the
`phishguard_mysql` volume).

### Option C: PythonAnywhere (free hosting, good for demos)

**Step 1:** Create an account at <https://www.pythonanywhere.com>, then open a **Bash console**.

**Step 2: Get the code and install it**

```bash
git clone https://github.com/Bilalabbasid/PFYP.git ~/PFYP
```
```bash
cd ~/PFYP && python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

If the free disk quota is too small for scikit-learn, set `ML_ENABLED=0`; the rules still work.

**Step 3:** On the **Databases** tab, set a MySQL password and create a database called `phishguard`.

**Step 4: Create `~/PFYP/.env`** (replace `USERNAME` and the password):

```
SECRET_KEY=<long random value>
DATABASE_URL=mysql+pymysql://USERNAME:<db password>@USERNAME.mysql.pythonanywhere-services.com/USERNAME$phishguard
SESSION_COOKIE_SECURE=1
BEHIND_PROXY=1
```

**Step 5: Create the tables, the model and the administrator**

```bash
.venv/bin/flask --app run db upgrade
```
```bash
.venv/bin/python ml/build_dataset.py && .venv/bin/python ml/train_model.py
```
```bash
.venv/bin/flask --app run create-admin
```

**Step 6: Set up the web app**

1. On the **Web** tab: *Add a new web app* → *Manual configuration* → *Python 3.11*.
2. Set **Virtualenv** to `/home/USERNAME/PFYP/.venv`.
3. Open the **WSGI configuration file** link, delete its contents and paste:

   ```python
   import sys
   path = "/home/USERNAME/PFYP"
   if path not in sys.path:
       sys.path.insert(0, path)
   from wsgi import app as application
   ```

4. Turn on **Force HTTPS**, then click **Reload**. The site is live at `https://USERNAME.pythonanywhere.com`.

### Running a production server on Windows

gunicorn does not run on Windows. Use waitress, which is already in `requirements.txt`:

```bash
waitress-serve --listen=0.0.0.0:8000 wsgi:app
```

---

## 7. Tests and evaluation

```bash
python -m pytest -q
```

84 automated tests cover:

- URL validation and feature extraction
- classification of safe, suspicious and phishing samples
- authentication: lock-out, open-redirect protection, password policy
- history privacy between users, and admin authorisation
- XSS escaping, CSRF and security headers
- the API, the ML layer, and whether the migrations match the models

Detection accuracy on the bundled sample dataset (3,000 URLs):

```bash
python ml/evaluate.py
```
```bash
python ml/evaluate.py --ml
```

| Mode | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Rules only | 98.8 % | 98.2 % | 99.4 % | 98.8 % |
| Rules + ML | 99.5 % | 99.0 % | 99.9 % | 99.5 % |

**Read these numbers with care.** The phishing half of the sample dataset is *synthetic*, built
from known phishing patterns, and the rules target the same patterns. The ML row also includes URLs
the model was trained on. The numbers show the system works as designed, not its real-world
accuracy. For a fair evaluation, use an independent public dataset: save it as a CSV with
`url,label` columns (1 = phishing, 0 = legitimate) and run
`python ml/evaluate.py --data your.csv` and `python ml/train_model.py --data your.csv`.
Suitable sources are PhiUSIIL (UCI), PhishTank / OpenPhish, and Tranco top sites for legitimate URLs.

Known weakness: legitimate sites that are not on the trusted list and have login or account pages
and hyphenated names (e.g. `t-mobile.com/login`) may be marked *Suspicious*.

---

## 8. How detection works

```
URL → validation → feature extraction → rule engine (+ optional ML) → 0–100 risk score → classification → explanation → history
```

- **Features** (`app/detection/features.py`):
  - **Lengths and counts:** lengths, counts of special characters, digits, hyphens and subdomain levels.
  - **Address tricks:** IP hosts (including decimal and hex forms), `@` credentials, unusual ports,
    and punycode / Unicode look-alike letters.
  - **Where it points:** link shorteners, free hosting platforms, abused TLDs, government and
    education TLDs, redirects (and whether the redirect target is suspicious), and risky file
    downloads.
  - **Wording and impersonation:** suspicious keywords, a brand name on an unofficial domain, and
    typosquatting (`paypa1`, `arnazon`, `yaahoo`, `chsae`).
  - **Randomness:** random-looking domain names.
- **Rules** (`app/detection/rules.py`): 27 weighted rules. Recognised legitimate and gov/edu
  domains subtract points.
  - The score maps to a verdict: 0–29 Likely Safe, 30–59 Suspicious, 60–100 Likely Phishing.
  - Two high-severity indicators always mean at least Likely Phishing; one always means at least
    Suspicious.
- **ML** (`app/detection/ml.py`, `ml/train_model.py`): a Random Forest trained on the same
  42 features.
  - The final score is `0.6 × rules + 0.4 × ML`.
  - The model can raise the risk freely, but it can only lower the explainable rule score when it
    is very confident the link is safe (< 10 % phishing probability).

---

## 9. Project structure, API, security

```
app/
  detection/   validators, features, knowledge lists, rules, ml, engine
  auth/ main/ awareness/ admin/ api/    Flask blueprints (routes)
  templates/   Jinja2 pages (Bootstrap 5)
  static/      css/style.css, js/ (main, quiz, context_check, admin, theme)
  models.py forms.py services.py utils.py seed.py cli.py
migrations/    Alembic database migrations
database/      mysql_migrations.sql
ml/            build_dataset.py, train_model.py, evaluate.py, data/urls.csv
tests/         pytest suite
config.py  run.py (development)  wsgi.py (production)
setup.bat / setup.sh / run.bat   one-command setup and start
Dockerfile  docker-compose.yml  Procfile  requirements.txt  .env.example
```

**API**

```
POST /api/v1/scan     {"url": "..."}   analyse and store (counts in admin stats)
POST /api/v1/analyze  {"url": "..."}   analyse only, nothing stored
GET  /api/v1/health
```

**Security measures**
- **Passwords and logins:**
  - passwords are hashed (Werkzeug scrypt)
  - accounts lock after repeated failed logins
  - login errors are generic
  - logout is POST-only
- **Forms and redirects:**
  - CSRF tokens on every form
  - open-redirect protection on `?next=`
- **Output escaping:**
  - Jinja escapes all output, and the article formatter escapes HTML first
  - scanned links are never rendered as clickable links
  - CSV export is protected against formula injection
- **HTTP headers and cookies:** Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`,
  HttpOnly and SameSite cookies.
- **Access control:** users see only their own scans, and admin pages require the admin role.

**Limitations:** URL-only analysis gives a risk assessment, not a guarantee. Compromised legitimate
sites and new techniques can be missed. The brand and trusted-domain lists need periodic updates.
There are no live reputation lookups, by design: the link is never contacted.

---

## 10. Troubleshooting

| Problem | Fix |
|---|---|
| `python` is not recognised | Reinstall Python and tick "Add python.exe to PATH", or use `py` instead of `python` on Windows. |
| `flask` is not recognised | Activate the virtual environment first (step 3), or use `.venv\Scripts\flask` / `.venv/bin/flask`. |
| PowerShell blocks `Activate.ps1` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or use Command Prompt. |
| Port 5000 already in use | Set `PORT=5001` in `.env`. |
| "Database not ready" warning with MySQL | Run `flask --app run db upgrade` and check `DATABASE_URL`. |
| `table ... already exists` during `db upgrade` on an old SQLite file | Run `flask --app run db stamp head` once, or delete `instance/phishguard.db`. |
| Admin dashboard says "No model file found" | Run `python ml/build_dataset.py` then `python ml/train_model.py`. |
| Page looks unstyled | Bootstrap and fonts load from a CDN, so check your internet connection. The app still works without them. |
