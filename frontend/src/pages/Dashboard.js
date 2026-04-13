import React, { useState, useEffect } from 'react';
import { 
  Bluetooth, 
  Wifi, 
  AlertTriangle, 
  Users, 
  TrendingUp,
  Clock,
  Shield
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import './Dashboard.css';

const Dashboard = () => {
  const [systemStatus, setSystemStatus] = useState({
    bluetooth_devices: 0,
    wifi_networks: 0,
    active_threats: 0,
    agents_online: 0,
    new_devices: 0,
    unsecured_networks: 0,
    critical_threats: 0,
    offline_agents: 0
  });

  const [networkActivity, setNetworkActivity] = useState([]);
  const [threatTimeline, setThreatTimeline] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSystemStatus();
    fetchNetworkActivity();
    fetchThreatTimeline();
    
    // Refresh data every 30 seconds
    const interval = setInterval(() => {
      fetchSystemStatus();
      fetchNetworkActivity();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  const fetchSystemStatus = async () => {
    try {
      const response = await fetch('/api/status');
      const data = await response.json();
      setSystemStatus(data);
    } catch (error) {
      console.error('Error fetching system status:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchNetworkActivity = async () => {
    try {
      const response = await fetch('/api/network-activity');
      const data = await response.json();
      setNetworkActivity(data.activity || []);
    } catch (error) {
      console.error('Error fetching network activity:', error);
    }
  };

  const fetchThreatTimeline = async () => {
    try {
      const response = await fetch('/api/threat-timeline');
      const data = await response.json();
      setThreatTimeline(data.timeline || []);
    } catch (error) {
      console.error('Error fetching threat timeline:', error);
    }
  };

  const statusCards = [
    {
      title: 'Bluetooth Devices',
      value: systemStatus.bluetooth_devices,
      change: `+${systemStatus.new_devices} new devices detected`,
      changeType: 'positive',
      icon: Bluetooth,
      color: '#3b82f6'
    },
    {
      title: 'Wi-Fi Networks',
      value: systemStatus.wifi_networks,
      change: `+${systemStatus.unsecured_networks} unsecured network`,
      changeType: 'positive',
      icon: Wifi,
      color: '#10b981'
    },
    {
      title: 'Active Threats',
      value: systemStatus.active_threats,
      change: `${systemStatus.critical_threats} critical, 1 warning`,
      changeType: 'negative',
      icon: AlertTriangle,
      color: '#ef4444'
    },
    {
      title: 'Agents Online',
      value: `${systemStatus.agents_online}/15`,
      change: `-${systemStatus.offline_agents} agents offline`,
      changeType: 'negative',
      icon: Users,
      color: '#8b5cf6'
    }
  ];

  if (loading) {
    return (
      <div className="dashboard">
        <div className="loading">
          <div className="loading-spinner"></div>
          <p>Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <div className="system-status">
          <div className="status-indicator">
            <div className="status-dot active"></div>
            <span>System Active</span>
          </div>
          <span className="status-subtitle">Monitoring</span>
        </div>
      </div>

      {/* Status Cards */}
      <div className="status-cards">
        {statusCards.map((card, index) => {
          const Icon = card.icon;
          return (
            <div key={index} className="status-card">
              <div className="card-header">
                <div className="card-icon" style={{ backgroundColor: card.color }}>
                  <Icon size={24} />
                </div>
                <div className="card-content">
                  <h3>{card.title}</h3>
                  <div className="card-value">{card.value}</div>
                  <div className={`card-change ${card.changeType}`}>
                    {card.change}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts Section */}
      <div className="charts-section">
        <div className="chart-container">
          <div className="chart-header">
            <h3>Network Activity</h3>
            <p>Real-time traffic analysis</p>
          </div>
          <div className="chart-content">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={networkActivity}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2a3e" />
                <XAxis 
                  dataKey="time" 
                  stroke="#a0a0a0"
                  fontSize={12}
                />
                <YAxis 
                  stroke="#a0a0a0"
                  fontSize={12}
                  domain={[0, 100]}
                />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: '#1a1a2e',
                    border: '1px solid #2a2a3e',
                    borderRadius: '8px',
                    color: '#ffffff'
                  }}
                />
                <Line 
                  type="monotone" 
                  dataKey="packets" 
                  stroke="#3b82f6" 
                  strokeWidth={2}
                  dot={{ fill: '#3b82f6', strokeWidth: 2, r: 4 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="timeline-container">
          <div className="timeline-header">
            <h3>Threat Timeline</h3>
            <p>Recent security events</p>
          </div>
          <div className="timeline-content">
            {threatTimeline.map((event, index) => (
              <div key={index} className="timeline-item">
                <div className="timeline-icon">
                  <Shield size={16} />
                </div>
                <div className="timeline-content">
                  <div className="timeline-title">{event.type}</div>
                  <div className="timeline-time">
                    <Clock size={12} />
                    {event.timestamp}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;






