# Shree Nathela Medical Stores

Professional pharmacy management system with manual purchase entry, batch-wise inventory, sales/invoices, returns, expiry control, supplier/customer intelligence, profit reporting and audit history.

## Important design choice
OCR and Gemini are **not required** by this version. Manual purchase entry is the source of truth, so the pharmacy remains operational even if an AI provider is unavailable, rate-limited or changed. An optional AI assistant can be added later without making stock/billing depend on it.

## Purchase workflow
1. Open **Purchases** and create a purchase.
2. Enter supplier, invoice and date.
3. Enter every medicine line: company, batch, MFD, expiry, quantity, free/scheme quantity, rate, discount, GST, MRP and net rate.
4. If the same medicine/company/batch was previously stored, MFD/expiry/cost/MRP can be recalled automatically.
5. Review the calculated line totals and purchase total.
6. An owner or authorized staff member can confirm the purchase to add quantity + free quantity to stock.

## Sales workflow
Sales select available batches ordered by earliest expiry, deduct stock atomically, record cost/profit data, support payment method and discount, and generate a printable invoice. Sales returns validate against the originally sold quantity and restore stock to the same batch.

## Start in VS Code
```cmd
npm.cmd install
npm.cmd start
```
Then open `http://localhost:3000`.

First-run login: `admin` / `ChangeMe123!`. Change the password before real use.

## Access levels
- **Owner**: full access to financial reports, revenue, profit, customers, suppliers, documents, users, settings, audit logs, inventory and pharmacy operations.
- **Authorized staff**: can create sales, purchases, bills, returns and operational stock/medicine changes, but cannot access financial reports, sales history, customer intelligence, supplier intelligence, owner administration or confidential purchase history.
- **Staff**: can view medicines, stock, expiry/near-expiry items and operational alerts only. They cannot create sales/purchases or access confidential business information.

Permissions are enforced by the server/API, not only by hiding menu buttons.

## Backup
The system keeps SQLite as the primary database. Owner-only **Download full backup** creates one `.snmsbackup` file containing a consistent SQLite database copy plus uploaded medicine images and purchase-bill files. The server also creates an automatic local backup every `AUTO_BACKUP_HOURS` (default 24) and retains the latest seven local bundles.

For real disaster protection, periodically download the full backup and store it on a separate trusted device or secure cloud storage. A backup on the same physical disk cannot protect against disk failure or theft.

## Production settings
Create `.env` from `.env.example` and set a strong `SESSION_SECRET`. SQLite remains the database engine in this version and is accessed through the Node.js API. Multiple users can use the same deployed application through that server; the server enforces role permissions and SQLite transactions.

Before real business use, use HTTPS, a strong unique session secret, regular off-machine backups, and test restoring a backup on a separate machine. SQLite is intentionally retained for this version; a later PostgreSQL migration can be done if transaction volume, branches or server scale require it.

## Initial accounts

On a completely new database (when no users exist), the app creates these five accounts:

| Username | Temporary password | Access |
|---|---|---|
| `owner` | `1234` | Owner — full access |
| `auth01` | `Auth01@SNMS2026!` | Authorized Staff — pharmacy operations, no confidential reports |
| `auth02` | `Auth02@SNMS2026!` | Authorized Staff — pharmacy operations, no confidential reports |
| `staff01` | `Staff01@SNMS2026!` | Staff — stock, expiry and alerts only |
| `staff02` | `Staff02@SNMS2026!` | Staff — stock, expiry and alerts only |

**Change every temporary password before real business use.** The Owner can reset staff passwords from Administration, and every signed-in user can change their own password from the top bar.

These seed accounts are created only when the database has no users. Existing databases are not overwritten or reseeded.
