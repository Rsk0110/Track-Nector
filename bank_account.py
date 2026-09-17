"""
Banking System — Account class
Concepts demonstrated: class methods, class variables, objects (OOP)
"""

from datetime import datetime
import hashlib
import json
import secrets
import base64
import os
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory


class Account:
    """Represents a single bank account."""

    # ---- Class variables (shared by every Account instance) ----
    MIN_BALANCE = 1
    _total_accounts = 0          # tracks how many accounts have been created
    _next_account_number = 1001  # simple auto-incrementing account number

    def __init__(self, holder_name, initial_deposit=1, password=None):
        if initial_deposit < Account.MIN_BALANCE:
            raise ValueError(
                f"Initial deposit must be at least CA${Account.MIN_BALANCE}"
            )
        if not password:
            raise ValueError("A password is required.")

        self.holder_name = holder_name
        self.account_number = Account._next_account_number
        self.balance = initial_deposit
        self.transactions = []
        self._password_salt = secrets.token_bytes(16)
        self._password_hash = self._hash_password(password)

        # Update class-level bookkeeping
        Account._next_account_number += 1
        Account._total_accounts += 1

        self._log("Account Opened", initial_deposit)

    def _hash_password(self, password):
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self._password_salt, 200_000
        )

    def verify_password(self, password):
        candidate = self._hash_password(password)
        return secrets.compare_digest(candidate, self._password_hash)

    @classmethod
    def from_record(cls, record):
        """Rebuild an account from the private on-disk record."""
        account = cls.__new__(cls)
        account.holder_name = record["holder_name"]
        account.account_number = record["account_number"]
        account.balance = record["balance"]
        account.transactions = record["transactions"]
        account._password_salt = base64.b64decode(record["password_salt"])
        account._password_hash = base64.b64decode(record["password_hash"])
        return account

    def to_record(self):
        return {
            "holder_name": self.holder_name,
            "account_number": self.account_number,
            "balance": self.balance,
            "transactions": self.transactions,
            "password_salt": base64.b64encode(self._password_salt).decode("ascii"),
            "password_hash": base64.b64encode(self._password_hash).decode("ascii"),
        }

    # ---- Instance methods ----

    def deposit(self, amount):
        """Add money to the account."""
        if amount <= 0:
            raise ValueError("Deposit amount must be positive.")

        self.balance += amount
        self._log("Deposit", amount)
        return self.balance

    def withdraw(self, amount, purpose="Cash withdrawal"):
        """
        Remove money from the account.
        Rules:
          - Cannot withdraw more than the current balance.
          - Balance can never drop below MIN_BALANCE (CA$1).
        """
        if amount <= 0:
            raise ValueError("Withdrawal amount must be positive.")
        purpose = purpose.strip()
        if not purpose:
            raise ValueError("Enter what this money was spent on.")

        if amount > self.balance:
            raise ValueError("Insufficient balance for this withdrawal.")

        if self.balance - amount < Account.MIN_BALANCE:
            raise ValueError(
                f"Withdrawal denied: balance cannot go below "
                f"CA${Account.MIN_BALANCE}."
            )

        self.balance -= amount
        self._log("Withdraw", amount, purpose)
        return self.balance

    def spent_total(self):
        return sum(
            transaction["amount"]
            for transaction in self.transactions
            if transaction["type"] == "Withdraw"
        )

    def spending_breakdown(self):
        breakdown = {}
        for transaction in self.transactions:
            if transaction["type"] == "Withdraw":
                purpose = transaction.get("purpose", "Cash withdrawal")
                breakdown[purpose] = breakdown.get(purpose, 0) + transaction["amount"]
        return breakdown

    def balance_inquiry(self):
        """Return the current balance."""
        return self.balance

    def statement(self):
        """Return a readable transaction history."""
        lines = [f"Statement for {self.holder_name} (A/C #{self.account_number})"]
        for t in self.transactions:
            lines.append(f"  {t['time']}  {t['type']:<15} CA${t['amount']:>10.2f}  "
                         f"-> Balance: CA${t['balance']:.2f}")
        return "\n".join(lines)

    def _log(self, txn_type, amount, purpose=None):
        transaction = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": txn_type,
            "amount": amount,
            "balance": self.balance,
        }
        if purpose:
            transaction["purpose"] = purpose
        self.transactions.append(transaction)

    # ---- Class methods ----

    @classmethod
    def total_accounts(cls):
        """Return the total number of accounts created so far."""
        return cls._total_accounts

    # ---- Dunder helpers ----

    def __str__(self):
        return (f"Account #{self.account_number} | {self.holder_name} | "
                f"Balance: CA${self.balance:.2f}")


def account_data(account, unlocked=False):
    """Return only the account details allowed at the current lock state."""
    data = {
        "holderName": account.holder_name,
        "accountNumber": account.account_number,
        "locked": not unlocked,
    }
    if unlocked:
        data["balance"] = account.balance
        data["transactions"] = account.transactions
        data["totalSpent"] = account.spent_total()
        data["spendingByPurpose"] = account.spending_breakdown()
    return data


accounts = []
unlocked_accounts = {}
SOURCE_DATA_FILE = Path(__file__).with_name("accounts.json")
DATA_FILE = Path(os.environ.get(
    "LEDGER_DATA_FILE", SOURCE_DATA_FILE
))


def save_accounts():
    """Persist accounts atomically so a partial write cannot corrupt the data."""
    payload = {
        "total_accounts": Account._total_accounts,
        "next_account_number": Account._next_account_number,
        "accounts": [account.to_record() for account in accounts],
    }
    temporary_file = DATA_FILE.with_suffix(".tmp")
    temporary_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary_file.replace(DATA_FILE)


def load_accounts():
    """Restore accounts and account-number bookkeeping when the server starts."""
    if not DATA_FILE.exists():
        if DATA_FILE == SOURCE_DATA_FILE or not SOURCE_DATA_FILE.exists():
            return
        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        DATA_FILE.write_bytes(SOURCE_DATA_FILE.read_bytes())
    payload = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    accounts.extend(Account.from_record(record) for record in payload["accounts"])
    Account._total_accounts = payload["total_accounts"]
    Account._next_account_number = payload["next_account_number"]


app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


def request_payload():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object.")
    return payload


def find_account(account_number):
    account = next(
        (item for item in accounts if item.account_number == account_number),
        None,
    )
    if account is None:
        raise LookupError("Account not found.")
    return account


def authorize_account(account):
    token = request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token[7:]
    if unlocked_accounts.get(token) is not account:
        raise PermissionError("Unlock this account before viewing its amount.")


@app.get("/api/health")
def health_check():
    return jsonify({"status": "ok"})


@app.get("/api/accounts")
def list_accounts():
    return jsonify({
        "accounts": [account_data(account) for account in accounts],
        "totalAccounts": Account.total_accounts(),
    })


@app.post("/api/accounts")
def create_account():
    payload = request_payload()
    name = str(payload.get("holderName", "")).strip()
    if not name:
        raise ValueError("Enter an account holder name.")
    password = str(payload.get("password", ""))
    if len(password) < 4:
        raise ValueError("Password must be at least 4 characters.")
    account = Account(name, float(payload["initialDeposit"]), password)
    accounts.append(account)
    save_accounts()
    return jsonify({"account": account_data(account)}), 201


@app.post("/api/accounts/<int:account_number>/<action>")
def account_action(account_number, action):
    payload = request_payload()
    account = find_account(account_number)

    if action == "unlock":
        if not account.verify_password(str(payload.get("password", ""))):
            raise PermissionError("Incorrect password.")
        token = secrets.token_urlsafe(32)
        unlocked_accounts[token] = account
        return jsonify({
            "token": token,
            "account": account_data(account, unlocked=True),
        })

    if action == "delete":
        if not account.verify_password(str(payload.get("password", ""))):
            raise PermissionError("Incorrect password.")
        accounts.remove(account)
        Account._total_accounts -= 1
        for token, unlocked_account in list(unlocked_accounts.items()):
            if unlocked_account is account:
                del unlocked_accounts[token]
        save_accounts()
        return jsonify({
            "accountNumber": account_number,
            "totalAccounts": Account.total_accounts(),
        })

    authorize_account(account)
    amount = float(payload["amount"])
    if action == "deposit":
        account.deposit(amount)
    elif action == "withdraw":
        account.withdraw(amount, str(payload.get("purpose", "")))
    else:
        return jsonify({"error": "Not found."}), 404
    save_accounts()
    return jsonify({"account": account_data(account, unlocked=True)})


@app.get("/")
@app.get("/index.html")
def serve_frontend():
    return send_from_directory(Path(__file__).parent, "index.html")


@app.errorhandler(PermissionError)
def handle_permission_error(error):
    return jsonify({"error": str(error)}), 403


@app.errorhandler(ValueError)
def handle_bad_request(error):
    return jsonify({"error": str(error)}), 400


app.register_error_handler(KeyError, handle_bad_request)
app.register_error_handler(TypeError, handle_bad_request)
app.register_error_handler(json.JSONDecodeError, handle_bad_request)


@app.errorhandler(LookupError)
def handle_missing_account(error):
    return jsonify({"error": str(error)}), 404


load_accounts()


# ------------------------------------------------------------------
# Demo / manual test — run this file directly to see it in action
# ------------------------------------------------------------------
if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    print(f"Ledger & Co. is running at http://{host}:{port}")
    app.run(host=host, port=port)
