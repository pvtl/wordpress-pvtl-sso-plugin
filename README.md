# A Boilerplate Wordpress Plugin by Pivotal

This is a boilerplate plugin which, by default:

- Creates a new custom post type
- Creates a new taxonomy
- Adds the defaults for outputting and theming the front-end

## Creating your own plugin

### Step 1.

_*The following should be run from your plugins directory_

__1.1 Clone the repo__

```bash
git clone https://github.com/pvtl/wp-boilerplate-plugin.git <YOUR_NEW_PLUGIN_NAME>
```

__1.2 Remove .git - we're starting a new plugin after all__

```bash
cd <YOUR_NEW_PLUGIN_NAME> && rm -rf .git
```

__1.3 Automatically rename the plugin__

```bash
bash rename-plugin.sh
```

__1.4 Delete rename-plugin.sh - you don't need it anymore__

```bash
rm rename-plugin.sh
```

### Step 2.

- Activate the plugin
- Import the `<this_plugin_dir>/custom-fields/acf-export.json` into __ACF > Tools__
- Modify the fields and __Export the JSON__ file + __Generate the PHP__ (replacing the existing file contents in `<this_plugin_dir>/custom-fields/`)
- Update the front-end templates to include any of the fields you need

---

# Plugin Placeholder Wordpress Plugin by Pivotal

- A `plugin-placeholder` custom post type
- A `plugin-placeholder-category` taxonomy
- Plugin Placeholder fields added to the post type
- Front-end templates (listing and single) to output the fields

## Prerequisites

- Wordpress
- Advanced Custom Fields Pro installed and activated

The default front-end templates make use of [Foundation](https://foundation.zurb.com/) - however you can override these in your theme if you need something different.

## Installation

_*The following should be run from your plugins directory_

```bash
git clone https://github.com/pvtl/wp-plugin-placeholders.git pvtl-plugin-placeholders
rm -rf pvtl-plugin-placeholders/.git
```

- Activate the plugin
- Update the project's `.gitignore` so that the plugin is included in the repo

## How do I...?

### Modify the front-end layout?

By default, the plugin will use the templates found in `<plugin_dir>/resouces/views/*.php`.

You can easily override these templates, by creating the respective templates in your theme, naming them:

| File Name | Desc. |
| --- | --- |
| `single-plugin-placeholder.php` | The single post template (overrides single.php) |
| `archive-plugin-placeholder.php` | The listing template (overrides archive.php) |

### Add extra fields?

__Are the extra field/s specific for this project?__

- Simply create a new ACF group and add the fields, targeted to this post type
- You'll then need to override the front-end template/s to output the additional fields

__Should these new field/s be default for all projects?__

- Import the `/custom-fields/acf-export.json` into ACF > Tools
- Modify the fields
- __Export the JSON__ file + __Generate the PHP__ (replacing the existing files)
- Update the front-end templates to include the fields
- Commit the changes back to the GIT repo
