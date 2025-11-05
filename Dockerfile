FROM node:20-alpine
WORKDIR /usr/src/app

# Install production deps only
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Copy application sources
COPY . .

ENV NODE_ENV=production
EXPOSE 3001

CMD ["npm", "start"]
