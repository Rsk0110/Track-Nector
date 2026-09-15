"""
Banking System — Account class
Concepts demonstrated: class methods, class variables, objects (OOP)
"""

from datetime import datetime
import hashlib
import json
import secrets
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


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
DATA_FILE = Path(__file__).with_name("accounts.json")


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
        return
    payload = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    accounts.extend(Account.from_record(record) for record in payload["accounts"])
    Account._total_accounts = payload["total_accounts"]
    Account._next_account_number = payload["next_account_number"]


class BankingRequestHandler(BaseHTTPRequestHandler):
    """Small JSON API and static-file server for the passbook UI."""

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length))

    def _authorized_account(self, account):
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        if unlocked_accounts.get(token) is not account:
            raise PermissionError("Unlock this account before viewing its amount.")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/accounts":
            self._send_json({
                "accounts": [account_data(account) for account in accounts],
                "totalAccounts": Account.total_accounts(),
            })
            return

        if self.path in ("/", "/index.html"):
            body = Path(__file__).with_name("index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self._send_json({"error": "Not found."}, 404)

    def do_POST(self):
        try:
            payload = self._read_json()
            parts = self.path.strip("/").split("/")

            if parts == ["api", "accounts"]:
                name = str(payload.get("holderName", "")).strip()
                if not name:
                    raise ValueError("Enter an account holder name.")
                password = str(payload.get("password", ""))
                if len(password) < 4:
                    raise ValueError("Password must be at least 4 characters.")
                account = Account(
                    name, float(payload["initialDeposit"]), password
                )
                accounts.append(account)
                save_accounts()
                self._send_json({"account": account_data(account)})
                return

            if len(parts) == 4 and parts[:2] == ["api", "accounts"]:
                account_number = int(parts[2])
                account = next(
                    account for account in accounts
                    if account.account_number == account_number
                )

                if parts[3] == "unlock":
                    password = str(payload.get("password", ""))
                    if not account.verify_password(password):
                        raise PermissionError("Incorrect password.")
                    token = secrets.token_urlsafe(32)
                    unlocked_accounts[token] = account
                    self._send_json({
                        "token": token,
                        "account": account_data(account, unlocked=True),
                    })
                    return

                if parts[3] == "delete":
                    password = str(payload.get("password", ""))
                    if not account.verify_password(password):
                        raise PermissionError("Incorrect password.")
                    accounts.remove(account)
                    for token, unlocked_account in list(unlocked_accounts.items()):
                        if unlocked_account is account:
                            del unlocked_accounts[token]
                    save_accounts()
                    self._send_json({
                        "accountNumber": account_number,
                        "totalAccounts": Account.total_accounts(),
                    })
                    return

                self._authorized_account(account)
                amount = float(payload["amount"])
                if parts[3] == "deposit":
                    account.deposit(amount)
                elif parts[3] == "withdraw":
                    account.withdraw(amount, str(payload.get("purpose", "")))
                else:
                    self._send_json({"error": "Not found."}, 404)
                    return
                save_accounts()
                self._send_json({"account": account_data(account, unlocked=True)})
                return

            self._send_json({"error": "Not found."}, 404)
        except PermissionError as error:
            self._send_json({"error": str(error)}, 403)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            self._send_json({"error": str(error)}, 400)
        except StopIteration:
            self._send_json({"error": "Account not found."}, 404)


# ------------------------------------------------------------------
# Demo / manual test — run this file directly to see it in action
# ------------------------------------------------------------------
if __name__ == "__main__":
    load_accounts()
    server = ThreadingHTTPServer(("127.0.0.1", 8000), BankingRequestHandler)
    print("Ledger & Co. is running at http://127.0.0.1:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()
