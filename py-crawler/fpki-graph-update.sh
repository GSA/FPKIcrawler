#------------------------------------------------------
# Setup important variables
#------------------------------------------------------
# SCRIPT DIRECTORY
SCRIPT_DIRECTORY=$(pwd)
# Secret file location
ACCESS_TOKEN_FILE="$SCRIPT_DIRECTORY/py_crawler/secrets/accesstoken"
SIGNING_KEY_PUB="$SCRIPT_DIRECTORY/py_crawler/secrets/signing_key.pub"
SIGNING_KEY="$SCRIPT_DIRECTORY/py_crawler/secrets/signing_key"
GH_USER_FILE="$SCRIPT_DIRECTORY/py_crawler/secrets/gh_user"
GH_EMAIL_FILE="$SCRIPT_DIRECTORY/py_crawler/secrets/gh_email"

#------------------------------------------------------
# Confirm env variable (if run from doocker) is present
#------------------------------------------------------
# Directory where we will install the Playbooks site from github
if [ -v REPO_DIR ]; then
  echo "Git Repo Directory set by docker to $REPO_DIR"
else
  echo "No \$REPO_DIR set. Setting to ../REPO"
  REPO_DIR="../REPO"
fi

if ! test -d $REPO_DIR; then
    # If the playbooks site doesn't exist here, create it
    echo "Creating $REPO_DIR"
    mkdir $REPO_DIR
fi

# Directory where we will keep the output of the command
if [ -v OUTPUT_DIR ]; then
  echo "Output Directory set by docker to $OUTPUT_DIR"
else
  echo "No \$OUTPUT_DIR set. Setting to ../OUTPUT"
  OUTPUT_DIR="../OUTPUT"
fi

#------------------------------------------------------
# Confirm git user information is present
#------------------------------------------------------
if test -f "$GH_USER_FILE"; then
  # Set GH Username
  GH_USER=$(cat "$GH_USER_FILE")
else
  echo No gh username at $GH_USER_FILE
  exit 1
fi

if test -f "$GH_EMAIL_FILE"; then
  # Set GH Email address
  GH_EMAIL=$(cat "$GH_EMAIL_FILE")
else
  echo No gh email at $GH_EMAIL_FILE
  exit 1
fi


#------------------------------------------------------
# Confirm secret is present
#------------------------------------------------------
if test -f "$ACCESS_TOKEN_FILE"; then
  # Set Access Token
  GH_TOKEN=$(cat "$ACCESS_TOKEN_FILE")
else
  echo No secret file present at $ACCESS_TOKEN_FILE
  exit 1
fi

#------------------------------------------------------
# Configuring signing keys 
# (this should only need to be done once, but is low impact, so we'll just do it every time)
#------------------------------------------------------
if test -f "$SIGNING_KEY_PUB" -a -f "$SIGNING_KEY"; then
  echo "Starting ssh-agent"
  eval $(ssh-agent) > /dev/null

  echo "Adding private signing key to ssh-agent"
  # Set permissions properly
  chmod 0600 $SIGNING_KEY
  ssh-add $SIGNING_KEY
else
  echo Signing keys not found at $SIGNING_KEY or $SIGNING_KEY_PUB
  exit 1
fi

#------------------------------------------------------
# Set up GIT Variables
#------------------------------------------------------
# GIT REPO URL
REPO="GSA/idmanagement.gov"
# BRANCH FOR THIS RUN
BRANCH=$(date +%m%d)-fpki-graph-update


#------------------------------------------------------
# Run py_crawler
#------------------------------------------------------
echo "Running py_crawler. This will take a minute..."
poetry run python -m py_crawler

#------------------------------------------------------
# Update Playbooks site with new artifacts
#------------------------------------------------------

(
  echo "Executing gh auth login"
  echo $GH_TOKEN | gh auth login --with-token
  gh auth setup-git
  cd "$REPO_DIR" || { echo "Playbooks directory does not exist!"; exit; }

  # See if we've already initialized the git repo here
  if [ "$(git rev-parse --is-inside-work-tree)" = "true" ]; then
    # switch to staging branch
    echo "Switching to 'staging' branch"
    git switch -f staging
    # sync the repo
    echo "Repo found. Syncing..."
    gh repo sync --force
    echo "Deleting branches that have been merged"
    git branch -d `git branch --merged | xargs`
    echo "Deleting local references to branches that have been deleted on remote"
    git fetch --prune
  else
    # initialize and update the repo
    echo "Initializing the playbooks REPO"
    gh repo clone $REPO .
    gh repo set-default $REPO
  fi

  # Set the user identifiers and credentials
  echo "Setting username"
  git config user.name $GH_USER
  echo "Setting email address"
  git config user.email $GH_EMAIL
  echo "Configuring Git with public signing key"
  git config gpg.format ssh
  git config user.signingkey $SIGNING_KEY_PUB

  echo "Checking for local branch for the current run"
  if [ "$(git branch --list $BRANCH)" = "" ]; then
    # Create a branch for this run
    echo "Creating a branch for the current Run"
    git checkout -B "$BRANCH"
  else
    echo "Branch exists. Switching..."
    git switch $BRANCH
  fi

  # Update the site with the new artifacts
  echo "Updating site with new artifacts"
  cp "$OUTPUT_DIR/CACertificatesValidatingToFederalCommonPolicyG2.p7b" _implement/tools
  cp "$OUTPUT_DIR/fpki-certs.gexf" _implement/tools
  cp "$OUTPUT_DIR/crawler-lastrun.json" _implement/tools
  sed -e "s/\*\*Last Update\*\*: .*/\*\*Last Update\*\*: $(date +"%B %d, %Y")/" _implement/fpki_notifications.md > _implement/fpki_notifications.md.tmp
  mv _implement/fpki_notifications.md.tmp _implement/fpki_notifications.md

  # Check for open PR
  # OPEN_PR=$(gh pr list --head $(date +%m%d)-fpki-graph-update --json number)

  # Submit the playbooks updates to the git repo
  echo "Adding updates"
  git add -A
  echo "Creating Signed Commit"
  git commit -S -m "automatic crawler update"
  echo "Submitting updates to origin"
  git push --all

  # Create Issue, record the output to a variable
  echo "Creating Issue"
  ISSUE=$(gh issue create --repo "$REPO" --title "$(date +%m%d) FPKI Graph Update"  --body "Automatically Created")

  # Parse out the issue number
  ISSUE_NUM=$(echo $ISSUE | cut -f 7 -d "/")

  # Open a PR linked to the Issue
  # echo "Creating PR"
  # gh pr create --repo "$REPO" --head "$BRANCH" --base "staging" --title "$(date +%m%d) Fpki Graph Update" --body "Closes #$ISSUE_NUM"
)