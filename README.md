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
# 1. Get it ready (to use a repo outside of packagist)
composer config repositories.pvtl-sso git https://github.com/pvtl/wordpress-pvtl-sso-plugin

# 2. Install the Plugin - we want all updates from this major version (while non-breaking)
composer require "pvtl/pvtl-sso:~1.0"

# 3. Activate the plugin
wp plugin activate pvtl-sso --allow-root
```

## Versioning

_Do not manually create tags_.

Versioning comprises of 2 things:

- Wordpress plugin version
    - The version number used by Wordpress on the plugins screen (and various other peices of functionality to track the version number)
    - Controlled in `./pvtl-sso.php` by `* Version: x.x.x` (line 10)
- Composer dependency version
    - The version Composer uses to know which version of the plugin to install
    - Controlled by Git tags

Versioning for this plugin is automated using a Github Action (`./.github/workflows/version-update.yml`).
To release a new version, simply change the `* Version: x.x.x` (line 10) in `./pvtl-sso.php` - the Github Action will take care of the rest.
