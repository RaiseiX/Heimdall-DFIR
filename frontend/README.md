# Frontend

React/Vite investigation interface for Heimdall DFIR.

## Stack

- React 18 and React Router 6
- Vite 5
- Tailwind CSS 3
- Axios
- Socket.io client
- Zustand
- D3, Cytoscape, Recharts
- TanStack Table and TanStack Virtual
- i18next and react-i18next

## Commands

```bash
npm install
npm run dev
npm run build
npm run preview
npm run typecheck
npm run i18n:check
```

The Vite dev server runs on port `3000`. Local API calls are expected to use the configured Vite proxy or the Docker/Traefik route depending on the workflow.

## Structure

```text
frontend/src/
├── components/          Shared and domain UI components
│   ├── ui/              Reusable UI primitives
│   ├── timeline/        Timeline and investigation timeline components
│   ├── supertimeline/   Super Timeline modules when present
│   ├── networkmap/      Network exploration UI
│   ├── upload/          Upload and memory upload components
│   └── ...
├── constants/           Shared constants
├── data/                Static product data
├── hooks/               Reusable stateful behavior
├── i18n/                Translation files and i18n setup
├── pages/               Route-level screens
├── services/            Frontend service helpers
├── state/               Shared client state stores
├── types/               Shared TypeScript types
└── utils/               API client, formatting, preferences, color rules
```

## UI Boundaries

- `pages/` owns route composition.
- `components/` owns presentation and interaction.
- `hooks/` owns reusable stateful behavior.
- `services/` and `utils/api.js` own transport calls.
- `state/` owns persistent and cross-panel client state.
- `i18n/fr.json` and `i18n/en.json` should stay synchronized; run `npm run i18n:check` after text changes.

## Product Expectations

Heimdall is an investigation interface. Frontend changes should preserve density, scannability, case context, evidence state, and analyst speed.

Avoid moving domain rules into JSX when they belong in services, utilities, or backend contracts. Case-scoped preferences and timeline state should be explicit about what is local-only and what is synchronized with the backend.

## Related Docs

- [Root README](../README.md)
- [UI architecture](../docs/ui.md)
- [Design system](../docs/design-system.md)
- [Architecture](../docs/architecture.md)
- [Workflows](../docs/workflows.md)
