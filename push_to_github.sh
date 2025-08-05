#!/bin/bash

# GitHub Push Helper Script for NexusController
# This script helps you push the NexusController to GitHub

echo "==================================="
echo "NexusController GitHub Push Helper"
echo "==================================="
echo ""

# Check if git remote is already configured
if git remote | grep -q "origin"; then
    echo "✓ Git remote 'origin' already configured:"
    git remote -v
    echo ""
    read -p "Do you want to push to the existing remote? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Pushing to existing remote..."
        git push -u origin main
        echo "✓ Push completed!"
    else
        echo "Skipping push. You can update the remote with:"
        echo "  git remote set-url origin <new-url>"
    fi
else
    echo "No git remote configured. Let's set it up!"
    echo ""
    echo "First, create a new repository on GitHub:"
    echo "1. Go to: https://github.com/new"
    echo "2. Repository name: NexusController (or your choice)"
    echo "3. Leave it empty (no README/license/gitignore)"
    echo "4. Click 'Create repository'"
    echo ""
    read -p "Press Enter when you've created the repository..."
    echo ""
    
    echo "Now, enter your GitHub details:"
    read -p "GitHub username: " username
    read -p "Repository name (default: NexusController): " reponame
    reponame=${reponame:-NexusController}
    
    echo ""
    echo "Choose connection method:"
    echo "1. HTTPS (easier, works everywhere)"
    echo "2. SSH (more secure, requires SSH key setup)"
    read -p "Enter choice (1 or 2): " choice
    
    if [ "$choice" = "2" ]; then
        remote_url="git@github.com:${username}/${reponame}.git"
    else
        remote_url="https://github.com/${username}/${reponame}.git"
    fi
    
    echo ""
    echo "Adding remote: $remote_url"
    git remote add origin "$remote_url"
    
    echo "Pushing to GitHub..."
    git push -u origin main
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✓ Successfully pushed to GitHub!"
        echo "View your repository at: https://github.com/${username}/${reponame}"
    else
        echo ""
        echo "⚠ Push failed. Common issues:"
        echo "- If using HTTPS: You may need to enter your GitHub username and password/token"
        echo "- If using SSH: Make sure your SSH key is added to GitHub"
        echo "- GitHub now requires personal access tokens instead of passwords for HTTPS"
        echo "  Create one at: https://github.com/settings/tokens"
        echo ""
        echo "To retry, run: git push -u origin main"
    fi
fi

echo ""
echo "==================================="
echo "Additional GitHub Setup Commands:"
echo "==================================="
echo "Add a description to your repo:"
echo "  gh repo edit --description 'Enterprise Infrastructure Management Platform'"
echo ""
echo "Add topics/tags:"
echo "  gh repo edit --add-topic infrastructure,monitoring,security,enterprise"
echo ""
echo "Create a release:"
echo "  gh release create v2.0.0 --title 'NexusController v2.0' --notes 'Enterprise release with full security and scalability'"