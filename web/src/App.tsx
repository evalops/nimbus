import { BrowserRouter, Route, Routes, Navigate } from "react-router-dom";

import { Layout } from "./components/Layout";
import { OverviewPage } from "./pages/OverviewPage";
import { ObservabilityPage } from "./pages/ObservabilityPage";
import { AgentsPage } from "./pages/AgentsPage";
import { LogsPage } from "./pages/LogsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { JobDetailPage } from "./pages/JobDetailPage";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<OverviewPage />} />
          <Route path="observability" element={<ObservabilityPage />} />
          <Route path="agents" element={<AgentsPage />} />
          <Route path="logs" element={<LogsPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="jobs/:jobId" element={<JobDetailPage />} />
          <Route path="jobs" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
