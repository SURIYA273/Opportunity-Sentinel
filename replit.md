# Workspace

## Overview

pnpm workspace monorepo using TypeScript. Each package manages its own dependencies.
This project includes a Student Opportunity Verifier web app that helps students detect scholarship/internship scams.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5 (Node.js proxy) + FastAPI (Python analysis engine)
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)
- **Frontend**: React + Vite + Tailwind + Framer Motion + Lucide React

## Structure

```text
artifacts-monorepo/
├── artifacts/              # Deployable applications
│   ├── api-server/         # Express API server (proxies to Python backend)
│   ├── python-api/         # Python FastAPI analysis engine
│   └── opportunity-verifier/ # React + Vite frontend
├── lib/                    # Shared libraries
│   ├── api-spec/           # OpenAPI spec + Orval codegen config
│   ├── api-client-react/   # Generated React Query hooks
│   ├── api-zod/            # Generated Zod schemas from OpenAPI
│   └── db/                 # Drizzle ORM schema + DB connection
├── scripts/                # Utility scripts
├── pnpm-workspace.yaml     # pnpm workspace
├── tsconfig.base.json      # Shared TS options
├── tsconfig.json           # Root TS project references
└── package.json            # Root package
```

## Services

- **Frontend** (port 20352) — React + Vite app at `/`
- **Express API** (port 8080) — Proxy server at `/api`
- **Python FastAPI** (port 8001) — Analysis engine (internal, not exposed publicly)

## API Flow

1. Frontend sends `POST /api/analyze` with `{ url: string }`
2. Express server proxies to Python FastAPI at port 8001
3. Python performs: SSL check, WHOIS domain age, scam keyword scan, sensitive input count, domain reputation
4. Returns trust score (0-100), grade (A+ to F), flags, and reasons

## Analysis Logic (Python)

- **SSL Check**: Uses `ssl` + `socket` to verify HTTPS certificates
- **Domain Age**: Uses `python-whois` — domains < 6 months = high risk
- **Scam Keywords**: BeautifulSoup scrapes page, scans for financial/urgency phrases
- **Data Harvesting**: Counts sensitive HTML inputs (SSN, bank, Aadhaar, etc.)
- **Domain Reputation**: `.edu/.gov/.org` = trusted; `.xyz/.top/.click` = risky

## Packages

### `artifacts/opportunity-verifier` (`@workspace/opportunity-verifier`)

React + Vite frontend. Uses Framer Motion for animations, Lucide React for icons.
- Entry: `src/main.tsx`
- App: `src/App.tsx`
- Pages: `src/pages/Home.tsx`
- Components: `src/components/Gauge.tsx`, `src/components/StepLoader.tsx`

### `artifacts/api-server` (`@workspace/api-server`)

Express 5 API server. Proxies `/api/analyze` to Python FastAPI.
- Routes: `src/routes/analyze.ts` (proxy), `src/routes/health.ts`

### `artifacts/python-api`

Python FastAPI analysis engine. Not a pnpm package.
- `src/main.py` — FastAPI app, runs on port 8001
- `src/analyzer.py` — All analysis logic

### `lib/api-spec` (`@workspace/api-spec`)

OpenAPI 3.1 spec. Run codegen: `pnpm --filter @workspace/api-spec run codegen`
