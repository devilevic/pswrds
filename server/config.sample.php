<?php
/*
 * pswrds server settings.
 *
 * 1. Copy this file and name the copy  pswrds-config.php
 * 2. Put it ONE FOLDER ABOVE public_html (in your home folder), so it can never be downloaded.
 *    If you can't, name it config.php and put it next to api.php instead.
 * 3. Fill in the database details from cPanel > MySQL Databases.
 */
return [
    // Namecheap: cPanel usernames are prefixed, e.g. "cpuser_pswrds"
    'dsn'    => 'mysql:host=localhost;dbname=CPUSER_pswrds;charset=utf8mb4',
    'user'   => 'CPUSER_pswrds',
    'pass'   => 'PUT-THE-DATABASE-PASSWORD-HERE',

    // Any long random text. Used to hash visitor IPs for rate limiting.
    'secret' => 'PUT-A-LONG-RANDOM-STRING-HERE',

    // Password for the private statistics page. At least 12 characters; leave empty to switch the page off.
    'admin_password' => '',

    // Payments. Leave both NOWPayments settings (or all three BTCPay settings) empty and pswrds stays free and unlimited.
    // The moment one provider is filled in, every vault that exists at that point gets lifetime access,
    // and new vaults get 'free_records' records per wallet until they pay.

    // NOWPayments (nowpayments.io): Settings > Payments > API keys, and Settings > Payments > Instant payment notifications
    'nowpayments_key'        => '',   // API key
    'nowpayments_ipn_secret' => '',   // IPN secret key
    'nowpayments_sandbox'    => false, // true only for tests with a sandbox account (account-sandbox.nowpayments.io)

    // Or BTCPay Server on your own server (used only if the NOWPayments settings are empty)
    'btcpay_url'   => '',   // e.g. https://pay.pswrds.com
    'btcpay_store' => '',   // Store ID: BTCPay > Store settings > General
    'btcpay_key'   => '',   // API key with "Create an invoice" and "View invoices" permissions for that store
    'price_usd'    => '20',
    'pay_tolerance' => 0.9,   // a payment of at least 90% of the requested crypto amount counts as paid (network fees, rate changes)
    'free_records' => 10,

    // Invitation codes requested on the extra-features page
    'invites_per_ip'  => 3,     // per IP address per day
    'invites_per_day' => 500,   // in total per day
];
