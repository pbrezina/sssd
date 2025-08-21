#!/usr/bin/env bash
set -e -o pipefail

# Usage
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <github-repo> <pr-id> <authors-json-path>" >&2
  exit 1
fi

scriptdir=`realpath \`dirname "$0"\``
wd=`pwd`

# Initial setup
GITHUB_REPOSITORY=$1
PR_ID=$2
AUTHORS_FILE=$3

OWNER=`echo "$GITHUB_REPOSITORY" | cut -d / -f 1`
REPOSITORY=`echo "$GITHUB_REPOSITORY" | cut -d / -f 2`
PR_URL="https://github.com/$OWNER/$REPOSITORY/pull/$PR_ID"
PR_REVIEWERS=`gh pr view --repo "$OWNER/$REPOSITORY" "$PR_ID" --json reviews --jq '.reviews.[] | select(.state == "APPROVED") | .author.login' | sort`
PR_COMMITS=`gh pr view --repo "$OWNER/$REPOSITORY" "$PR_ID" --json commits --jq '.commits.[] | "* \(.oid) - \(.messageHeadline)"'`
PR_COMMITS_SHA=`gh pr view --repo "$OWNER/$REPOSITORY" "$PR_ID" --json commits --jq .commits.[].oid`
PR_COMMITS_FIRST=`echo "$PR_COMMITS_SHA" | head -1`

echo "GitHub Repository: $OWNER/$REPOSITORY"
echo "GitHub Pull Request: $PR_URL"
echo "Reviewers: `echo $PR_REVIEWERS | tr '\n' ' '`"
echo "First Commit: $PR_COMMITS_FIRST"
echo "Commits:"
echo "$PR_COMMITS"
echo ""
echo "Action Directory: $scriptdir"
echo "Working Directory: $wd"
echo ""

set -x

pushd /home/pbrezina/workspace/sssd.test

git config trailer.where end
git config trailer.ifexists addIfDifferent

trailers=""
for name in $PR_REVIEWERS; do
    value=`jq -r --arg user "$name" '(.[] | select(.github_username == $user) | "\(.name) <\(.email)>") // "\($user) <https://github.com/\($user)>"' $AUTHORS_FILE`
    trailers+="--trailer 'Reviewed-by: $value' "
done

if [ ! -z "$trailers" ]; then
    git rebase "$PR_COMMITS_FIRST~1" -x "git commit --amend --no-edit $trailers"
fi
