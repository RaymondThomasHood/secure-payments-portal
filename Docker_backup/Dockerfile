# Use a lightweight Node.js base image
FROM node:20-alpine

# Set the working directory inside the container
WORKDIR /app

# Install build tools and dependencies for sqlite3
RUN apk add --no-cache python3 make g++ && \
    npm install -g node-gyp

# Copy package.json and package-lock.json first (for caching)
COPY package*.json ./

# Install dependencies, including rebuilding sqlite3
RUN npm install

# Copy the rest of the application code, including certificates
COPY . .

# Expose the port the app runs on
EXPOSE 5001

# Command to run the app
CMD ["node", "server.js"]