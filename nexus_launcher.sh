#!/bin/bash
# NexusController v2.0 Launcher Script

set -e

VERSION="2.0.0"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 NexusController v${VERSION} Launcher"
echo "Project Directory: $PROJECT_DIR"
echo "================================"

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "Python Version: $python_version"

# Check if virtual environment exists
if [ ! -d "$PROJECT_DIR/venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv "$PROJECT_DIR/venv"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source "$PROJECT_DIR/venv/bin/activate"

# Install/update dependencies
if [ ! -f "$PROJECT_DIR/venv/installed" ] || [ "$PROJECT_DIR/requirements.txt" -nt "$PROJECT_DIR/venv/installed" ]; then
    echo "📥 Installing dependencies..."
    pip install --upgrade pip
    pip install -r "$PROJECT_DIR/requirements.txt"
    touch "$PROJECT_DIR/venv/installed"
else
    echo "✅ Dependencies up to date"
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p "$PROJECT_DIR/data"
mkdir -p "$PROJECT_DIR/logs"
mkdir -p "$PROJECT_DIR/plugins"
mkdir -p "$PROJECT_DIR/keys"

# Set permissions
chmod 700 "$PROJECT_DIR/data"
chmod 700 "$PROJECT_DIR/keys"

# Check for config file
if [ ! -f "$PROJECT_DIR/config.yaml" ]; then
    echo "⚠️  No config.yaml found, using defaults"
fi

echo "🎯 Starting NexusController..."
echo "================================"

# Start the application
cd "$PROJECT_DIR"
exec python3 nexus_controller_v2.py "$@"