import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Wifi, 
  AlertTriangle, 
  Package, 
  Target, 
  BarChart3, 
  FileText, 
  Shield, 
  Users, 
  List,
  Lock,
  Menu,
  X
} from 'lucide-react';
import './Layout.css';

const Layout = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();

  const menuItems = [
    { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/module1', icon: Wifi, label: 'Module 1 - Wi-Fi & Bluetooth' },
    { path: '/module3', icon: Package, label: 'Module 3 - Packet Capture' },
    { path: '/rogue', icon: AlertTriangle, label: 'Rogue Detection' },
    { path: '/attacks', icon: Target, label: 'Attack Detection' },
    { path: '/profiling', icon: BarChart3, label: 'Device Profiling' },
    { path: '/reports', icon: FileText, label: 'Forensic Reporting' },
    { path: '/mitigation', icon: Shield, label: 'Mitigation & Response' },
    { path: '/agents', icon: Users, label: 'Agents' },
    { path: '/logs', icon: List, label: 'Logs' }
  ];

  return (
    <div className="layout">
      {/* Top Navigation Bar */}
      <div className="top-nav">
        <div className="top-nav-left">
          <button 
            className="menu-toggle"
            onClick={() => setSidebarOpen(!sidebarOpen)}
          >
            {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
          <div className="browser-tabs">
            <div className="tab active">localhost:5173</div>
            <div className="tab">Kali Linux</div>
            <div className="tab">Kali Tools</div>
            <div className="tab">Kali Docs</div>
            <div className="tab">Kali Forums</div>
            <div className="tab">Kali NetHunter</div>
            <div className="tab">Exploit-DB</div>
            <div className="tab">Google Hacking DB</div>
            <div className="tab">OffSec</div>
          </div>
        </div>
        <div className="top-nav-right">
          <div className="search-icon">🔍</div>
          <div className="star-icon">⭐</div>
          <div className="zoom-level">80%</div>
          <div className="hamburger-menu">☰</div>
        </div>
      </div>

      {/* App Header */}
      <div className="app-header">
        <div className="user-info">
          <div className="user-avatar">A</div>
          <span>Admin</span>
        </div>
        <div className="header-actions">
          <button className="btn-start-scan">Start Scanning</button>
          <button className="btn-logout">Logout</button>
        </div>
      </div>

      <div className="layout-content">
        {/* Sidebar */}
        <div className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
          <div className="sidebar-header">
            <Lock className="sidebar-logo" size={24} />
            <span className="sidebar-title">BWF Toolkit</span>
          </div>
          <nav className="sidebar-nav">
            {menuItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`nav-item ${isActive ? 'active' : ''}`}
                  onClick={() => setSidebarOpen(false)}
                >
                  <Icon size={20} />
                  <span>{item.label}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Main Content */}
        <div className="main-content">
          {children}
        </div>
      </div>
    </div>
  );
};

export default Layout;






