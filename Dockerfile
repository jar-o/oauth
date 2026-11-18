# One image, two entrypoints:
#   server (default):  docker run -p 3000:3000 oauth2-demo
#   test client:       docker run -p 4000:4000 oauth2-demo node dist/client/index.js

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
USER node
EXPOSE 3000 4000
CMD ["node", "dist/server/index.js"]
