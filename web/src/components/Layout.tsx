import { type ReactNode } from "react";
import { NavLink, Outlet } from "react-router-dom";

import { useSettings } from "../hooks/useSettings";

import "./Layout.css";

export function Layout() {
  return (
    <div className="layout">
      <header className="layout__header">
        <div className="layout__brand">Nimbus Dashboard</div>
        <nav className="layout__nav">
          <NavItem to="/">Overview</NavItem>
          <NavItem to="/observability">Observability</NavItem>
          <NavItem to="/agents">Agents</NavItem>
          <NavItem to="/logs">Logs</NavItem>
          <NavItem to="/analytics">Analytics</NavItem>
          <NavItem to="/tools">Tools</NavItem>
          <NavItem to="/settings">Settings</NavItem>
        </nav>
      </header>
      <StatusBanner />
      <main className="layout__main">
        <Outlet />
      </main>
    </div>
  );
}

function NavItem({ to, children }: { to: string; children: ReactNode }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) => (isActive ? "layout__link layout__link--active" : "layout__link")}
      end={to === "/"}
    >
      {children}
    </NavLink>
  );
}

function StatusBanner() {
  const { settings } = useSettings();
  const missing: string[] = [];
  if (!settings.controlPlaneBase) missing.push("Control Plane URL");
  if (!settings.adminToken) missing.push("Admin token");
  if (!settings.agentToken) missing.push("Dashboard agent token");

  if (missing.length === 0) {
    return null;
  }

  return (
    <div className="layout__banner" role="alert">
      <strong>Configuration required:</strong> Please provide {missing.join(", ")} in Settings to unlock all features.
    </div>
  );
}
