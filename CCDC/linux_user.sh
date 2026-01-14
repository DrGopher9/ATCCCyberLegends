#!/bin/bash

#DO NOT USE THIS ON WEBMAIL!!!!
# Whitelist of users to keep (e.g., current user or important accounts)
WHITELIST=("root" "sysadmin" "$USER")

# Get a list of non-system users (UID >= 1000) from /etc/passwd
NON_SYSTEM_USERS=$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd)

# Array to store removed users for logging
REMOVED_USERS=()

echo "Identifying non-native users..."
for user in $NON_SYSTEM_USERS; do
    # Check if the user is in the whitelist
    if [[ " ${WHITELIST[@]} " =~ " ${user} " ]]; then
        echo "Skipping whitelisted user: $user"
    else
        echo "Removing user: $user"
        # Remove the user and their home directory
        sudo userdel -r "$user"
        if [ $? -eq 0 ]; then
            echo "User $user removed successfully."
            REMOVED_USERS+=("$user")
        else
            echo "Failed to remove user $user."
        fi
    fi
done

# Display a summary of removed users
if [ ${#REMOVED_USERS[@]} -gt 0 ]; then
    echo "Summary of removed users:"
    for removed in "${REMOVED_USERS[@]}"; do
        echo "- $removed"
    done
else
    echo "No users were removed."
fi

echo "Done."
