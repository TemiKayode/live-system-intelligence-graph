import React from "react";
import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import ServiceView from "./pages/ServiceView";
import PRCertificate from "./pages/PRCertificate";
import SearchPage from "./pages/SearchPage";
import "./App.css";

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-shell">
        <nav className="sidebar">
          <div className="logo">LSIG</div>
          <NavLink to="/" end>Services</NavLink>
          <NavLink to="/search">Search</NavLink>
          <NavLink to="/pr">PR Certificate</NavLink>
        </nav>
        <main className="content">
          <Routes>
            <Route path="/" element={<ServiceView />} />
            <Route path="/service/:service" element={<ServiceView />} />
            <Route path="/search" element={<SearchPage />} />
            <Route path="/pr" element={<PRCertificate />} />
            <Route path="/pr/:prId" element={<PRCertificate />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
