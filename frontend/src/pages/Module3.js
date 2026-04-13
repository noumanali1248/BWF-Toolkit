import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  Radio,
  TrendingUp,
  Shield,
  Eye,
  Clock
} from 'lucide-react';
import './Module3.css';

const Module3 = () => {
  const [allPackets, setAllPackets] = useState([]);
  const [suspiciousPackets, setSuspiciousPackets] = useState([]);
  const [statistics, setStatistics] = useState({
    total_packets: 0,
    packets_per_second: 0,
    protocols: {},
    suspicious_count: 0,
    top_ips: [],
    alert_types: {}
  });
  const [captureStatus, setCaptureStatus] = useState({
    running: false,
    interface: 'any',
    total_packets: 0,
    packets_per_second: 0
  });
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all'); // 'all', 'suspicious', 'normal'
  const [protocolFilter, setProtocolFilter] = useState('all');
  const [autoRefresh, setAutoRefresh] = useState(true);

  useEffect(() => {
    // Initial fetch
    fetchAllData();
    
    // Auto-refresh every 3 seconds if enabled
    let interval;
    if (autoRefresh) {
      interval = setInterval(() => {
        fetchAllData();
      }, 3000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh]);

  const fetchAllData = async () => {
    await Promise.all([
      fetchPackets(),
      fetchStatistics(),
      fetchCaptureStatus()
    ]);
    setLoading(false);
  };

  const fetchPackets = async () => {
    try {
      const response = await fetch('/api/live-capture/packets/all');
      const data = await response.json();
      
      if (data.all_packets) {
        setAllPackets(data.all_packets);
      }
      if (data.suspicious_packets) {
        setSuspiciousPackets(data.suspicious_packets);
      }
    } catch (error) {
      console.error('Error fetching packets:', error);
    }
  };

  const fetchStatistics = async () => {
    try {
      const response = await fetch('/api/live-capture/statistics');
      const data = await response.json();
      setStatistics(data);
    } catch (error) {
      console.error('Error fetching statistics:', error);
    }
  };

  const fetchCaptureStatus = async () => {
    try {
      const response = await fetch('/api/live-capture/status');
      const data = await response.json();
      setCaptureStatus(data);
    } catch (error) {
      console.error('Error fetching capture status:', error);
    }
  };

  const getFilteredPackets = () => {
    let filtered = [...allPackets];

    // Apply suspicious filter
    if (filter === 'suspicious') {
      filtered = filtered.filter(p => p.suspicious);
    } else if (filter === 'normal') {
      filtered = filtered.filter(p => !p.suspicious);
    }

    // Apply protocol filter
    if (protocolFilter !== 'all') {
      filtered = filtered.filter(p => p.protocol === protocolFilter);
    }

    return filtered;
  };

  const formatTime = (timestamp) => {
    const date = new Date(timestamp * 1000);
    return date.toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit',
      fractionalSecondDigits: 3
    });
  };

  const getProtocolColor = (protocol) => {
    const colors = {
      'TCP': '#4CAF50',
      'UDP': '#2196F3',
      'ICMP': '#FF9800',
      'ARP': '#9C27B0',
      'DNS': '#00BCD4',
      'HTTP': '#8BC34A',
      'HTTPS': '#4CAF50'
    };
    return colors[protocol] || '#607D8B';
  };

  const getAlertBadge = (alertType) => {
    const badges = {
      'PORT_SCAN': { color: '#f44336', icon: '🔍' },
      'DOS_ATTACK': { color: '#ff5722', icon: '⚠️' },
      'SYN_FLOOD': { color: '#ff9800', icon: '🌊' },
      'ICMP_FLOOD': { color: '#ffc107', icon: '⚡' },
      'ARP_SPOOFING': { color: '#9c27b0', icon: '🎭' },
      'ANOMALY': { color: '#e91e63', icon: '❗' }
    };
    return badges[alertType] || { color: '#607d8b', icon: '?' };
  };

  const filteredPackets = getFilteredPackets();

  if (loading) {
    return (
      <div className="module3-container">
        <div className="loading-spinner">
          <Activity className="spinner-icon" size={48} />
          <p>Loading packet capture data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="module3-container">
      {/* Header */}
      <div className="module3-header">
        <div className="header-title">
          <Radio className="header-icon" size={32} />
          <div>
            <h1>Module 3 - Packet Capture & Sniffing</h1>
            <p>Real-time packet analysis and anomaly detection</p>
          </div>
        </div>
        
        <div className="capture-controls">
          <div className="capture-status">
            {captureStatus.running ? (
              <>
                <div className="status-indicator running"></div>
                <span className="status-text">Live Capture Active</span>
              </>
            ) : (
              <>
                <div className="status-indicator stopped"></div>
                <span className="status-text">Capture Stopped</span>
              </>
            )}
          </div>
          
          <div className="capture-buttons">
            {captureStatus.running ? (
              <button className="btn-stop" onClick={async () => {
                try {
                  const response = await fetch('/api/live-capture/stop', { method: 'POST' });
                  const data = await response.json();
                  if (data.status === 'stopped') {
                    fetchAllData();
                  }
                } catch (error) {
                  console.error('Error stopping capture:', error);
                }
              }}>
                <XCircle size={16} /> Stop Capture
              </button>
            ) : (
              <button className="btn-start" onClick={async () => {
                try {
                  const response = await fetch('/api/live-capture/start', { method: 'POST' });
                  const data = await response.json();
                  if (data.status === 'started' || data.status === 'already_running') {
                    fetchAllData();
                  }
                } catch (error) {
                  console.error('Error starting capture:', error);
                }
              }}>
                <CheckCircle size={16} /> Start Capture
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon" style={{ backgroundColor: '#4CAF50' }}>
            <Activity size={24} />
          </div>
          <div className="stat-info">
            <div className="stat-value">{statistics.total_packets.toLocaleString()}</div>
            <div className="stat-label">Total Packets</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ backgroundColor: '#2196F3' }}>
            <TrendingUp size={24} />
          </div>
          <div className="stat-info">
            <div className="stat-value">{statistics.packets_per_second}</div>
            <div className="stat-label">Packets/Second</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ backgroundColor: '#f44336' }}>
            <AlertTriangle size={24} />
          </div>
          <div className="stat-info">
            <div className="stat-value">{statistics.suspicious_count}</div>
            <div className="stat-label">Suspicious Packets</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ backgroundColor: '#9C27B0' }}>
            <Shield size={24} />
          </div>
          <div className="stat-info">
            <div className="stat-value">{allPackets.length}</div>
            <div className="stat-label">Recent Packets</div>
          </div>
        </div>
      </div>

      {/* Protocol Distribution */}
      <div className="protocol-distribution">
        <h3><Eye size={20} /> Protocol Distribution</h3>
        <div className="protocol-bars">
          {Object.entries(statistics.protocols).map(([protocol, count]) => {
            const percentage = (count / statistics.total_packets) * 100;
            return (
              <div key={protocol} className="protocol-bar-item">
                <div className="protocol-info">
                  <span className="protocol-name">{protocol}</span>
                  <span className="protocol-count">{count} ({percentage.toFixed(1)}%)</span>
                </div>
                <div className="protocol-bar">
                  <div 
                    className="protocol-fill" 
                    style={{ 
                      width: `${percentage}%`,
                      backgroundColor: getProtocolColor(protocol)
                    }}
                  ></div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Alert Types Distribution */}
      {Object.keys(statistics.alert_types || {}).length > 0 && (
        <div className="alert-distribution">
          <h3><AlertTriangle size={20} /> Threat Distribution</h3>
          <div className="alert-badges">
            {Object.entries(statistics.alert_types).map(([type, count]) => {
              const badge = getAlertBadge(type);
              return (
                <div 
                  key={type} 
                  className="alert-badge"
                  style={{ borderLeft: `4px solid ${badge.color}` }}
                >
                  <span className="alert-icon">{badge.icon}</span>
                  <span className="alert-name">{type}</span>
                  <span className="alert-count">{count}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Filters and Controls */}
      <div className="controls-bar">
        <div className="filter-group">
          <label>Status Filter:</label>
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="all">All Packets</option>
            <option value="suspicious">🚨 Suspicious Only</option>
            <option value="normal">✓ Normal Only</option>
          </select>
        </div>

        <div className="filter-group">
          <label>Protocol Filter:</label>
          <select value={protocolFilter} onChange={(e) => setProtocolFilter(e.target.value)}>
            <option value="all">All Protocols</option>
            {Object.keys(statistics.protocols).map(protocol => (
              <option key={protocol} value={protocol}>{protocol}</option>
            ))}
          </select>
        </div>

        <div className="filter-group">
          <label>
            <input 
              type="checkbox" 
              checked={autoRefresh} 
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            Auto-refresh (3s)
          </label>
        </div>

        <div className="packet-count">
          Showing {filteredPackets.length} of {allPackets.length} packets
        </div>
      </div>

      {/* Packets Table */}
      <div className="packets-section">
        <h3>
          <Activity size={20} /> 
          Live Packet Stream - Complete Details
        </h3>
        
        <div className="packets-table-container">
          <table className="packets-table">
            <thead>
              <tr>
                <th>#</th>
                <th><Clock size={14} /> Time</th>
                <th>Protocol</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Ports</th>
                <th>Length</th>
                <th>Status</th>
                <th>Alert Type</th>
              </tr>
            </thead>
            <tbody>
              {filteredPackets.length === 0 ? (
                <tr>
                  <td colSpan="9" className="no-packets">
                    No packets captured yet. Capture is {captureStatus.running ? 'running' : 'stopped'}.
                  </td>
                </tr>
              ) : (
                filteredPackets.slice().reverse().map((packet, index) => (
                  <tr 
                    key={packet.id || index} 
                    className={packet.suspicious ? 'suspicious-row' : 'normal-row'}
                  >
                    <td className="packet-id">{packet.id}</td>
                    <td className="packet-time">{formatTime(packet.timestamp)}</td>
                    <td>
                      <span 
                        className="protocol-badge"
                        style={{ backgroundColor: getProtocolColor(packet.protocol) }}
                      >
                        {packet.protocol}
                      </span>
                    </td>
                    <td className="ip-address">{packet.src_ip || '-'}</td>
                    <td className="ip-address">{packet.dst_ip || '-'}</td>
                    <td className="ports">
                      {packet.src_port && packet.dst_port 
                        ? `${packet.src_port} → ${packet.dst_port}`
                        : '-'}
                    </td>
                    <td className="packet-length">{packet.length} B</td>
                    <td className="packet-status">
                      {packet.suspicious ? (
                        <span className="status-suspicious">
                          <XCircle size={16} /> Suspicious
                        </span>
                      ) : (
                        <span className="status-normal">
                          <CheckCircle size={16} /> Normal
                        </span>
                      )}
                    </td>
                    <td className="alert-type">
                      {packet.alert_type ? (
                        <span 
                          className="alert-type-badge"
                          style={{ 
                            backgroundColor: getAlertBadge(packet.alert_type).color 
                          }}
                        >
                          {getAlertBadge(packet.alert_type).icon} {packet.alert_type}
                        </span>
                      ) : (
                        '-'
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Top IPs */}
      {statistics.top_ips && statistics.top_ips.length > 0 && (
        <div className="top-ips-section">
          <h3>📊 Most Active IP Addresses</h3>
          <div className="top-ips-grid">
            {statistics.top_ips.slice(0, 10).map((item, index) => (
              <div key={index} className="top-ip-card">
                <span className="ip-rank">#{index + 1}</span>
                <span className="ip-address">{item.ip}</span>
                <span className="ip-count">{item.count} packets</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default Module3;

