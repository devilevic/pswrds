# pswrds

Zero-knowledge password manager with duress passphrases and decoy vaults. Live at **https://pswrds.com**.

- Everything is encrypted in the browser (PBKDF2-SHA256 + AES-256-GCM, Web Crypto API). The server stores eight fixed-size encrypted slots per vault and can't read them or tell how many are in use.
- One vault can hold several passphrases: wallets that open separate, ordinary-looking wallets, and duress passphrases that silently destroy chosen wallets and open a decoy.
- No email, no cookies, no third-party resources.

Security design and threat model: https://pswrds.com/security.html · Reporting vulnerabilities: see [SECURITY.md](SECURITY.md).

Licence: [GNU AGPL-3.0](LICENSE). Operated by SEMLIN s.r.o.

---

Zero-knowledge password manager with programmable passphrases.

## Folders

- `src/pswrds.html`: the app. Edit this.
- `server/api.php`: the storage API (PHP 8.1+, MySQL). Stores only encrypted slots.
- `server/.htaccess`: forces HTTPS, sets security headers, blocks private files.
- `server/config.sample.php`: template for the database settings.
- `server/pswrds-invites.php`: hashes of the 1000 invitation codes. Upload it next to `pswrds-config.php`, one folder above `public_html`.
- `invites/invitation-codes.xlsx`: the 1000 codes themselves. Private: never upload it.
- `static/stats.html`: private statistics page. Rename it to a hard-to-guess name when you deploy, and update the matching rule in `server/.htaccess`. Needs `admin_password` in `pswrds-config.php`.
- `static/duress-passphrase.html`: the page about duress passphrases, decoy vaults and hidden wallets (pswrds.com/duress-passphrase.html).
  Not linked from the home page, but indexed by search engines and linked from the FAQ. The old address
  4m5a1r920j5x.html redirects to it.
- `static/duress-passphrase.html` also has the **Request an invitation code** button.
- `static/faq.html`: public questions and answers (linked from the home page), with screenshots in `static/img/faq-*.webp`.
- `static/img/duress-passphrase-*.webp`: screenshots for that page. `static/img/og*.png`: link-preview images.
- `static/security.html`: public security design and threat model (linked from every page footer).
  `static/.well-known/security.txt`: how to report vulnerabilities. `SECURITY-REVIEW.md`: internal review notes (not uploaded).
- SEO: `build.py` writes `sitemap.xml` and fills the FAQPage structured data from each page's questions
  (pages marked with `<!-- faq-schema -->`). `static/robots.txt` points to the sitemap. Only the statistics page is noindex.
- `build.py` empties `public/` first, so upload the whole folder and delete files on the server that are no longer in it.
- `static/`: favicon, app icons, `manifest.webmanifest` and `sw.js` (lets phones install pswrds as an app).
- `public/`: what goes on the web server. Rebuild it with `python3 build.py`. Don't edit it by hand.

## Put it on Namecheap

1. cPanel > SSL/TLS Status: make sure pswrds.com has a certificate (AutoSSL).
2. cPanel > Select PHP Version: choose 8.1 or newer.
3. cPanel > MySQL Databases: create a database and a user, give the user ALL PRIVILEGES on it.
4. Copy `server/config.sample.php`, name it `pswrds-config.php`, fill in the database name, user, password and a long random secret.
   Upload it to your home folder, one level above `public_html`.
5. Upload everything inside `public/` into `public_html`.
   (`.htaccess` is hidden on a Mac: press Cmd+Shift+. in Finder to see it.)
6. Upload `server/pswrds-invites.php` next to `pswrds-config.php` (one folder above `public_html`).
7. Open https://pswrds.com. The status pill should say "Synced, encrypted". The tables are created on first use.

## Invitation codes

- Without a code, New vault creates an ordinary single wallet.
- With a valid code, it creates a main wallet that can add wallet and delete passphrases.
- Each code works once. The server records only that a code was used, not which vault used it.
- Both kinds of vault look identical on the server: eight slots of the same size.

## Invitation codes on request

- The duress passphrase page (`duress-passphrase.html`) has a **Request an invitation code** button.
- The browser first solves a small puzzle (a few seconds), which stops scripts without a CAPTCHA.
- Limits: `invites_per_ip` codes per IP per day (default 3) and `invites_per_day` in total (default 500), set in `pswrds-config.php`.
  IPs are stored only as keyed hashes and deleted after a day. The server doesn't store when a code was issued.
- **Create a vault with this code** passes the code to the sign-up form within the same browser tab, never in the address.
- The 1000 codes in `invitation-codes.xlsx` keep working for handing out by hand.

## Free tier and payments

- Payments are **off** until a provider is filled in `pswrds-config.php` (NOWPayments, or BTCPay as an alternative). Until then everything stays free and unlimited.
- At the moment they are switched on, every vault that exists gets lifetime access for free (once, shown as "Free lifetime (early users)" on the statistics page).
- New vaults then get `free_records` records per wallet (default 10). A one-time payment (`price_usd`, default 20) removes the limit for every wallet in the vault.
- The limit is enforced by the app, not the server: the server can't see records. Viewing, editing and deleting always keep working.
- How a payment works: the app asks the server for an invoice **without sending the vault id**. When the payment is confirmed,
  the server gives the app a license code, and the app applies it to the vault. The server stores only that the vault is paid,
  never which payment paid for it. A payment in progress is remembered (encrypted) inside the wallet, so it finishes even if the page was closed.

### Setting up NOWPayments (current choice)

1. Sign up at https://nowpayments.io and confirm your email.
2. Settings > Payments > **Payout wallets**: add your own Bitcoin address (and Monero, or any other coin you want). Payments are forwarded there.
3. Settings > Payments > **Coins settings**: switch on only the coins you want to accept (for example BTC and XMR).
4. Settings > Payments > **API keys**: create an API key.
5. Settings > Payments > **Instant payment notifications**: generate the **IPN secret key** and save it.
6. In `pswrds-config.php` (above `public_html`) add:

       'nowpayments_key'        => 'YOUR-API-KEY',
       'nowpayments_ipn_secret' => 'YOUR-IPN-SECRET',

   Upload it. Payments are on from the next request.
7. Test: temporarily add `'price_usd' => '1'` (check NOWPayments' minimum amount for the coin), create a new vault, add 10 records, pay. Then remove the line.

Small underpayments: a payment of at least 90% of the requested crypto amount counts as paid (`pay_tolerance`).
Wallets often subtract their network fee from the amount sent, and the rate can move while a payment confirms.

Support: if a payment didn't unlock someone's vault, check it in NOWPayments, then create a license code on the
statistics page ("License code for support") and give it to them. They enter it under "I have a license code".

NOWPayments tells pswrds about each payment by calling `https://pswrds.com/api.php?op=nowpayments_ipn`, signed with the IPN secret.
Nothing needs to be configured for that URL: the app sends it with every invoice.

### Alternative: BTCPay Server on your own VPS

Used only when the NOWPayments settings are empty.

1. Rent a VPS (Ubuntu 24.04, at least 4 GB RAM and 100 GB SSD for Bitcoin only, e.g. Namecheap VPS Quasar).
2. In Namecheap DNS, point a subdomain such as `pay.pswrds.com` at the VPS (A record).
3. Install BTCPay with the official Docker setup: https://docs.btcpayserver.org/Docker/ (use `BTCPAY_HOST=pay.pswrds.com`).
4. Create the admin account, then a store with default currency **USD**, and connect a Bitcoin wallet (xpub).
5. Account > API keys > Generate key with **Create an invoice** and **View invoices** for that store.
6. Fill in `btcpay_url`, `btcpay_store` and `btcpay_key` in `pswrds-config.php`.

## How the vault works

- Each username has 8 encrypted slots of identical size. Unused slots are random bytes.
- A passphrase becomes a key (PBKDF2-SHA256, 600,000 rounds, per-vault salt) that unlocks at most one slot (AES-256-GCM).
- Slot kinds: `main` (a wallet plus the map of all other slots), `wallet`, `wipe` (deletes chosen wallets), `wipeall`.
  A delete passphrase works once, then opens an empty wallet.
- Change passphrase: any wallet can change the passphrase it was opened with (only its own slot is re-encrypted).
  The main passphrase can also change any other passphrase from the Passphrases tab, and changing the main passphrase
  renews the write token in every slot it can open. If a wallet changes its own passphrase, the main passphrase can't open
  it any more: its slot is marked as such and stays reserved until released.
- Every slot has a version: a random number that changes on every save (never a counter, which would show which slots
  are in use). A save says which version it replaces; if another device saved that slot meanwhile,
  the server answers 409 "stale", nothing is overwritten, and the app reloads the vault.
- Back up: the app saves an encrypted backup file (all eight slots and the salt). "Open a backup file" on the unlock screen opens it
  in the browser's memory, and it can be restored to pswrds.com when the username has no vault there (lifetime access isn't included).
- Fingerprint unlock (one wallet per device, never Main): a platform passkey with the WebAuthn "prf" extension gives a
  device-only secret after a fingerprint/face check. HKDF of that secret encrypts {wallet key, username} in localStorage
  ("pswrds-quick"). The server isn't involved. Changing that wallet's passphrase on this device turns it off; if it was
  changed elsewhere, the next fingerprint unlock fails cleanly and removes the record. Needs iOS 18+, Android Chrome, or
  recent desktop Chrome/Safari; the button stays hidden where it isn't supported.
- Writes need the vault's write token, which is stored inside every real slot. The server keeps only its SHA-256 hash.
- The server rate-limits each IP (300 requests per 10 minutes) and stores IPs only as keyed hashes.

## Before a public launch

- Argon2id instead of PBKDF2.
- Hide which slot changed on save.
- Make sure hosting backups don't keep deleted vaults longer than you intend.
- Independent security audit.
