#!/usr/bin/env bash

#
#
# Creates a new Wordpress Plugin
# Essentially just finds/Replaces placeholder content
# with the new plugin's name
#
# Make sure you always run the plural version first
#
#

# Config
# =========================================================
RESET="\e[39m"
BLUE="\e[34m"
UNDERLINE="\e[4m"
NO_UNDERLINE="\e[0m"
FILLERSPACE="FILLERSPACE"
RAND=$(cat /dev/urandom | LC_CTYPE=C tr -dc 'a-z0-9' | fold -w 5 | head -n 1)

FIND_SINGULAR="Plugin\sPlaceholder"
FIND_PLURAL="Plugin\sPlaceholders"
# REPLACE_SINGULAR="Case\sStudy"
# REPLACE_PLURAL="Case\sStudies"

echo -e "${BLUE}\n?? Please enter the ${UNDERLINE}singular (& capitalised)${NO_UNDERLINE} name for the plugin/post-type: [eg. Case Stud${UNDERLINE}y${NO_UNDERLINE}] ${RESET}"
read -p "== " REPLACE_SINGULAR
if [[ -z "$REPLACE_SINGULAR" ]]; then
  echo "Please enter a name..."
  exit 1
fi

echo -e "${BLUE}\n?? Please enter the ${UNDERLINE}plural (& capitalised)${NO_UNDERLINE} name for the plugin/post-type: [eg. Case Stud${UNDERLINE}ies${NO_UNDERLINE}] ${RESET}"
read -p "== " REPLACE_PLURAL
if [[ -z "$REPLACE_PLURAL" ]]; then
  echo "Please enter a name..."
  exit 1
fi

FIND_SINGULAR_SLUG="plugin-placeholder"
FIND_PLURAL_SLUG="plugin-placeholders"
REPLACE_SINGULAR_SLUG=`echo "$REPLACE_SINGULAR" | tr " " - | tr '[:upper:]' '[:lower:]'`
REPLACE_PLURAL_SLUG=`echo "$REPLACE_PLURAL" | tr " " - | tr '[:upper:]' '[:lower:]'`

FIND_SINGULAR_LOWER="plugin\splaceholder"
FIND_PLURAL_LOWER="plugin\splaceholders"
REPLACE_SINGULAR_LOWER=`echo "$REPLACE_SINGULAR" | tr '[:upper:]' '[:lower:]' | sed -e 's/ /'"$FILLERSPACE"'/g'`
REPLACE_PLURAL_LOWER=`echo "$REPLACE_PLURAL" | tr '[:upper:]' '[:lower:]' | sed -e 's/ /'"$FILLERSPACE"'/g'`

FIND_SINGULAR_SPACELESS="PluginPlaceholder"
FIND_PLURAL_SPACELESS="PluginPlaceholders"
REPLACE_SINGULAR_SPACELESS=`echo "$REPLACE_SINGULAR" | tr -d " "`
REPLACE_PLURAL_SPACELESS=`echo "$REPLACE_PLURAL" | tr -d " "`

FIND_SINGULAR_UNDERSCORE="Plugin_Placeholder"
FIND_PLURAL_UNDERSCORE="Plugin_Placeholders"
REPLACE_SINGULAR_UNDERSCORE=`echo "$REPLACE_SINGULAR" | tr " " _`
REPLACE_PLURAL_UNDERSCORE=`echo "$REPLACE_PLURAL" | tr " " _`

FIND_SINGULAR_UNDERSCORE_LOWER="plugin_placeholder"
FIND_PLURAL_UNDERSCORE_LOWER="plugin_placeholders"
REPLACE_SINGULAR_UNDERSCORE_LOWER=`echo "$REPLACE_SINGULAR" | tr " " _ | tr '[:upper:]' '[:lower:]'`
REPLACE_PLURAL_UNDERSCORE_LOWER=`echo "$REPLACE_PLURAL" | tr " " _ | tr '[:upper:]' '[:lower:]'`

REPLACE_SINGULAR=`echo "$REPLACE_SINGULAR" | sed -e 's/ /'"$FILLERSPACE"'/g'`
REPLACE_PLURAL=`echo "$REPLACE_PLURAL" | sed -e 's/ /'"$FILLERSPACE"'/g'`

# Functions
# =========================================================
# Find/Replace File Names
replaceFileNames () {
  for file in $(find . -name '*'"$1"'*')
  do
    mv $file $(echo "$file" | sed -r 's|'"$1"'|'"$2"'|g')
  done
}

# Find/Replace contents of all files
replaceContents () {
    for file in $(find . -type f -name '*.php' -o -name '*.md' -o -name '*.json')
    do
      sed -i 's/'"$1"'/'"$2"'/g' $file
    done
}

# Run
# =========================================================
# Find/Replace filenames
replaceFileNames $FIND_PLURAL_SLUG $REPLACE_PLURAL_SLUG
replaceFileNames $FIND_SINGULAR_SLUG $REPLACE_SINGULAR_SLUG

# Find/Replace file contents
  # Cosmetic - eg. Case Study and Case Studies
replaceContents $FIND_PLURAL $REPLACE_PLURAL
replaceContents $FIND_SINGULAR $REPLACE_SINGULAR

  # Slugs - eg. case-study and case-studies
replaceContents $FIND_PLURAL_SLUG $REPLACE_PLURAL_SLUG
replaceContents $FIND_SINGULAR_SLUG $REPLACE_SINGULAR_SLUG

  # Lowercase - eg. case study and case studies
replaceContents $FIND_PLURAL_LOWER $REPLACE_PLURAL_LOWER
replaceContents $FIND_SINGULAR_LOWER $REPLACE_SINGULAR_LOWER

  # Space-less - eg. CaseStudy and CaseStudies
replaceContents $FIND_PLURAL_SPACELESS $REPLACE_PLURAL_SPACELESS
replaceContents $FIND_SINGULAR_SPACELESS $REPLACE_SINGULAR_SPACELESS

  # Underscore - eg. Case_Study and Case_Studies
replaceContents $FIND_PLURAL_UNDERSCORE $REPLACE_PLURAL_UNDERSCORE
replaceContents $FIND_SINGULAR_UNDERSCORE $REPLACE_SINGULAR_UNDERSCORE

  # Lowercase Underscore - eg. case_study and case_studies
replaceContents $FIND_SINGULAR_UNDERSCORE_LOWER $REPLACE_SINGULAR_UNDERSCORE_LOWER
replaceContents $FIND_PLURAL_UNDERSCORE_LOWER $REPLACE_PLURAL_UNDERSCORE_LOWER

  # Replace random string in ACF fields
replaceContents "5aebb" $RAND

  # Remove the $FILLERSPACE
replaceContents $FILLERSPACE " "
