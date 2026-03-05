Create python virtual environment:
python -m venv venv

Windows: venv\scripts\activate
linux: source venv/bin/activate

To exit: deactivate (both windows & linux)

Mail part:
export SMTP_SERVER="smtp.zoho.com"
export SMTP_PORT="465"
export FROM_EMAIL="xxxxxxxxxxxx"
export SMTP_PASSWORD="your_real_zoho_app_password"

export ABOUT_TO_EXPIRE_EMAIL="xxxxxxxxxx"
export ABOUT_TO_EXPIRE_CC="xxxxxxxxxxxx"
export EXPIRED_EMAIL="xxxxxxxxxxx"

