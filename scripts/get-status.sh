#!/usr/bin/env bash

checks=$(
    gh pr checks --repo SSSD/sssd 8071 --json state,workflow,name,link --jq '
    # First, sort the entire array by the "workflow" and "name" keys.
    sort_by(.workflow, .name) |

    # Then, iterate over each element in the sorted array.
    .[] |

    # A conditional check to determine the emoji based on the state.
    (if .state == "FAILURE" then "🔴"
    elif .state == "SUCCESS" then "🟢"
    elif .state == "CANCELLED" then "⚪"
    elif .state == "IN_PROGRESS" then "🟡"
    elif .state == "PENDING" then "⏳"
    else .state
    end
    ) as $emoji |

    # Another conditional check to format the output.
    # If the workflow is an empty string, print a simplified format.
    # Otherwise, print the full format including the workflow.
    if .workflow == "" then
        "\($emoji) \(.state)\t[\(.name)](\(.link))"
    else
        "\($emoji) \(.state)\t[\(.workflow) / \(.name)](\(.link))"
    end
    '
)

echo -e "$checks"