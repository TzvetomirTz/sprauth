# Sprauth authentication

## Features

- **Runtime:** Node.js
- **Framework:** Express 5.x
- **Language:** TypeScript 6.x
- **Module System:** ESM (`"type": "module"`)
- **Development Tooling:** `tsx` for fast execution and `nodemon` for auto-reloading.

---

## Prerequisites

Ensure you have the following installed:
- [Node.js](https://nodejs.org/) (v20.x or higher recommended)
- [npm](https://www.npmjs.com/)

---

## Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/TzvetomirTz/sprauth.git](https://github.com/TzvetomirTz/sprauth.git)
   cd sprauth

2. **Generate quantum safe pub/priv keys:**
   ```bash
   npx tsx ./scripts/keygen.tsx

3. **Run the docker container:**
   ```bash
   docker build -t sprauth-api .
   docker run -p 3000:3000 sprauth-api

