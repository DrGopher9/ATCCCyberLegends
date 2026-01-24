#!/bin/bash

# Define colors for output
GREEN="\033[1;32m"
RED="\033[1;31m"
RESET="\033[0m"

# Check if the script is being run as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR] Please run this script as root.${RESET}"
  exit 1
fi

# Determine the original user (not root)
ORIGINAL_USER=$(logname 2>/dev/null || echo $SUDO_USER)

if [ -z "$ORIGINAL_USER" ]; then
  echo -e "${RED}[ERROR] Could not determine the original user.${RESET}"
  exit 1
fi

# Get the home directory of the original user
ORIGINAL_HOME=$(getent passwd "$ORIGINAL_USER" | cut -d: -f6)

# Define the LinPEAS download URL
LINPEAS_URL="https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"

# Directory to store LinPEAS
TOOLS_DIR="/opt/linpeas"
LINPEAS_PATH="$TOOLS_DIR/linpeas.sh"

# Create the tools directory if it doesn't exist
if [ ! -d "$TOOLS_DIR" ]; then
  echo -e "${GREEN}[INFO] Creating directory: $TOOLS_DIR${RESET}"
  mkdir -p "$TOOLS_DIR"
fi

# Download LinPEAS with error handling
echo -e "${GREEN}[INFO] Downloading LinPEAS...${RESET}"
if ! curl -L -o "$LINPEAS_PATH" "$LINPEAS_URL"; then
  echo -e "${RED}[ERROR] Failed to download LinPEAS. Please check the URL or network connection.${RESET}"
  exit 1
fi

# Make the LinPEAS script executable
echo -e "${GREEN}[INFO] Making LinPEAS executable...${RESET}"
chmod +x "$LINPEAS_PATH"

# Define the output file location in the user's home directory
OUTPUT_FILE="$ORIGINAL_HOME/linpeas_output_$(date +%Y%m%d_%H%M%S).txt"

# Run LinPEAS and save the output
echo -e "${GREEN}[INFO] Running LinPEAS and saving output to: $OUTPUT_FILE${RESET}"
"$LINPEAS_PATH" | tee "$OUTPUT_FILE"

# Adjust file permissions so the original user can access it
chown "$ORIGINAL_USER:$ORIGINAL_USER" "$OUTPUT_FILE"

echo -e "${GREEN}[INFO] LinPEAS execution completed. Output saved to: $OUTPUT_FILE${RESET}"
