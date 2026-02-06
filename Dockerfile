# 1. Use a slim Node.js image to keep the plugin fast and small
# Note: As of January, 2026, when building this image, it uses Node.js version 25.2.1
# The 'node:slim' tag will automatically use the latest Node.js version every time the image is built
FROM node:slim

# 2. Set the working directory inside the container
WORKDIR /app

# 3. Copy package files first (to leverage Docker caching for faster builds)
COPY package*.json ./

# 4. Install production dependencies only
RUN npm install --omit=dev

# 5. Copy the rest of your source code
COPY . .

# 6. Ensure the entrypoint script is executable (important for Linux runners)
RUN chmod +x /app/entrypoint.sh

# 7. Set the Entrypoint
# This tells Docker to run the shell script first, which then calls your Node logic
ENTRYPOINT ["/app/entrypoint.sh"]