FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install --no-audit --no-fund
COPY . .
# Run vite build directly — bypasses whatever is in package.json "build" script
RUN npx vite build

FROM node:20-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist

# Static file server intégré — pas besoin de npm install
COPY server.js ./

# Run as non-root user
RUN chown -R node:node /app
USER node

EXPOSE 3000
CMD ["node", "server.js"]
