FROM node:24.22.2-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS build
WORKDIR /app
COPY package*.json ./
RUN npm install --no-audit --no-fund
COPY . .
# Run vite build directly — bypasses whatever is in package.json "build" script
RUN npx vite build

FROM node:24.22.2-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85
WORKDIR /app
COPY --from=build /app/dist ./dist

# Static file server intégré — pas besoin de npm install
COPY server.js ./

# Run as non-root user
RUN chown -R node:node /app
USER node

EXPOSE 3000
CMD ["node", "server.js"]
