# Task To Reward (Flask)

Advanced manual-controlled Task & Earn web app with User + Admin panels.

## Tech Stack
- Backend: Flask + SQLite
- Frontend: HTML/CSS + minimal JS-ready structure

## Default Admin Credentials
- Username: `admin`
- Password: `admin123`

## Features
- User registration/login (single account via unique contact)
- Task list with screenshot submission and anti-duplicate screenshot hash checking
- Admin manual screenshot approval/rejection with reason
- Wallet ledger (credits only on approval, debits on paid withdrawals)
- Withdrawal request flow with minimum withdrawal setting and one pending request limit
- Admin controls: tasks CRUD/toggle, user block/unblock, withdrawal manual payout, feature flags, minimum withdrawal
- Persistent records: users, tasks, submissions, wallet txns, withdrawals, admin actions
- Future-ready structure: sponsored tasks, ads, video ads, referral, telegram notifications, VIP, analytics, multi-withdraw methods

## Run
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install flask
python app.py
```
Then open http://localhost:5000

## Deployment
Can be deployed on Render/Hostinger as a standard Flask app.
