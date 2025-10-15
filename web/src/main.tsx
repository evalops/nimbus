import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { SettingsProvider } from "./context/SettingsContext";
import App from "./App.tsx";
import "./index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <SettingsProvider>
      <App />
    </SettingsProvider>
  </StrictMode>,
);
