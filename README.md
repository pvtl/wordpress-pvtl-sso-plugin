# Pivotal Agency SSO Wordpress Plugin

Utilising https://sso.pvtl.io - this is a Wordpress Authentication plugin, that allows staff (users with a valid @pivotalagency.com.au Google account) to login to Wordpress sites with minimal effort.

## What does it do?

- At `wp-login.php` - if the user inputs `pvtl` as the username and password and presses submit, it'll redirect to `sso.pvtl.io`
- Upon successful authentication with `sso.pvtl.io`, the user will be redirected back to the Wordpress site and logged in (as a Wordpress user/admin)
    - If the user's email *does not exist* as a Wordpress user:
        - A new user (using the details from SSO + a random, long password) will be created as an `admin` role _(The 'admin' role can of course be manually changed after creation)_
    - If the user *does exist* as a Wordpress user:
        - Automatically login as that user
        - On each login, the user's password will be changed to something long and unique (to prevent users from manually setting the password to bypass SSO)

## Installation

```bash
# 1. Clone the plugin into ./web/app/plugins/pvtl-sso
git clone git@github.com:pvtl/wordpress-pvtl-sso-plugin.git web/app/plugins/pvtl-sso

# 2. Activate the plugin
```
