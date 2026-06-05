FROM node:20-alpine

WORKDIR /app

# install system tools (optional, keep if you really need nmap)
RUN apk add --no-cache nmap nmap-scripts

COPY package*.json ./

# safer install (important for network issues)
RUN npm install --no-audit --no-fund --legacy-peer-deps

COPY . .

EXPOSE 3001

CMD ["node", "index.js"]