# Nimbus Dashboard (React + Vite)

This package contains the web dashboard for Nimbus. It is a Vite-powered React
application that consumes the control-plane and logging APIs to provide
operator views for jobs, agents, logs, and settings.

## Getting started

```bash
cd web
npm install
npm run dev
```

The dev server runs on <http://localhost:5173> with hot module reload. All API
requests are proxied to the configured control plane URL, so be sure to supply
valid base URLs and tokens from the **Settings** tab.

## Configuration & authentication

- **Control plane base URL** – required for job/agent APIs and metrics.
- **Logging service base URL** – optional override for `/logs/query`; falls
  back to the control plane host if omitted.
- **Admin token** – JWT used to mint a dashboard-scoped agent token and view
  protected admin resources.
- **Dashboard agent token** – bearer token used for read-only queries. Mint a
  limited TTL token via the Settings page.

All configuration is stored in `localStorage` so operators can refresh without
re-entering secrets.

## Builds

```bash
cd web
npm run build   # emits production assets in web/dist
```

The resulting static files can be served by any CDN or copied into a Nimbus
container image for production deployment.

## Testing & linting

- `npm run lint` – run the ESLint configuration shipped with Vite.
- `npm run build` – type-checks and creates a production build (used in CI).

The dashboard currently relies on the backend’s integration tests; add browser
automation (Playwright/Cypress) as future work.
