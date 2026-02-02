#!/bin/bash

echo "🚀 Starting User Management System..."

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install --production
fi

# Create database directory if needed
mkdir -p data

# Start the server
echo "🌐 Starting server on port ${PORT:-3000}..."
node server.js
