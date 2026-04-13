import React, { useState, useEffect } from 'react';
import { 
  Wifi, 
  Play, 
  Square, 
  Download, 
  RefreshCw,
  Signal,
  Shield,
  Clock,
  MapPin,
  Activity,
  BarChart3,
  PieChart
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  BarChart, 
  Bar, 
  PieChart as RechartsPieChart, 
  Cell,
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  Legend
} from 'recharts';
import './Module1.css';

const Module1 = () => {
  const [networks, setNetworks] = useState([]);
  const [scanStatus, setScanStatus] = useState({ scanning: false, last_scan: null });
  const [statistics, setStatistics] = useState({});
  const [loading, setLoading] = useState(false);
  const [selectedNetwork, setSelectedNetwork] = useState(null);

  useEffect(() => {
    fetchNetworks();
    fetchScanStatus();
    
    // Refresh data every 10 seconds
    const interval = setInterval(() => {
      fetchNetworks();
      fetchScanStatus();
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  const fetchNetworks = async () => {
    try {
      const response = await fetch('/api/networks');
      const data = await response.json();
      setNetworks(data.networks || []);
      setStatistics(data.statistics || {});
    } catch (error) {
      console.error('Error fetching networks:', error);
    }
  };

  const fetchScanStatus = async () => {
    try {
      const response = await fetch('/api/scan/status');
      const data = await response.json();
      setScanStatus(data);
    } catch (error) {
      console.error('Error fetching scan status:', error);
    }
  };

  const startScan = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/scan/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ duration: 30 }),
      });
      const data = await response.json();
      if (data.success) {
        // Start polling for results
        const pollInterval = setInterval(async () => {
          const statusResponse = await fetch('/api/scan/status');
          const statusData = await statusResponse.json();
          if (!statusData.scanning) {
            clearInterval(pollInterval);
            fetchNetworks();
            setLoading(false);
          }
        }, 2000);
      }
    } catch (error) {
      console.error('Error starting scan:', error);
      setLoading(false);
    }
  };

  const exportData = async (format) => {
    try {
      const response = await fetch(`/api/export/${format}`);
      const data = await response.json();
      
      if (format === 'json') {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `wifi_scan_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
        a.click();
        URL.revokeObjectURL(url);
      } else if (format === 'csv') {
        const csvContent = convertToCSV(data.csv_data);
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `wifi_scan_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Error exporting data:', error);
    }
  };

  const convertToCSV = (data) => {
    if (!data || data.length === 0) return '';
    
    const headers = Object.keys(data[0]);
    const csvRows = [
      headers.join(','),
      ...data.map(row => headers.map(header => `"${row[header] || ''}"`).join(','))
    ];
    return csvRows.join('\n');
  };

  const getSecurityColor = (security) => {
    if (security?.toLowerCase().includes('open')) return '#ef4444';
    if (security?.toLowerCase().includes('wpa3')) return '#10b981';
    if (security?.toLowerCase().includes('wpa2')) return '#3b82f6';
    if (security?.toLowerCase().includes('wpa')) return '#f59e0b';
    return '#6b7280';
  };

  const getSignalColor = (strength) => {
    if (strength >= 80) return '#10b981';
    if (strength >= 60) return '#f59e0b';
    if (strength >= 40) return '#f97316';
    return '#ef4444';
  };

  // Prepare chart data
  const securityChartData = Object.entries(statistics.device_types || {}).map(([type, count]) => ({
    name: type,
    value: count
  }));

  const signalChartData = networks.map(network => ({
    ssid: network.ssid?.substring(0, 10) + (network.ssid?.length > 10 ? '...' : ''),
    signal: network.signal_strength || 0
  }));

  const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4'];

  return (
    <div className="module1">
      <div className="module-header">
        <div className="header-content">
          <div className="header-title">
            <Wifi size={32} />
            <h1>Bluetooth & Wi-Fi Discovery Scanner</h1>
          </div>
          <p>Comprehensive wireless device discovery and network mapping</p>
        </div>
        <div className="header-actions">
          <button 
            className={`btn-scan ${scanStatus.scanning || loading ? 'scanning' : ''}`}
            onClick={startScan}
            disabled={scanStatus.scanning || loading}
          >
            {scanStatus.scanning || loading ? (
              <>
                <RefreshCw size={16} className="spinning" />
                Scanning...
              </>
            ) : (
              <>
                <Play size={16} />
                Start Scan
              </>
            )}
          </button>
          <button className="btn-export" onClick={() => exportData('json')}>
            <Download size={16} />
            Export JSON
          </button>
          <button className="btn-export" onClick={() => exportData('csv')}>
            <Download size={16} />
            Export CSV
          </button>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="stats-cards">
        <div className="stat-card">
          <div className="stat-icon">
            <Wifi size={24} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{statistics.total_networks || 0}</div>
            <div className="stat-label">Total Networks</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">
            <Shield size={24} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{statistics.secured_networks || 0}</div>
            <div className="stat-label">Secured Networks</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">
            <Activity size={24} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{statistics.open_networks || 0}</div>
            <div className="stat-label">Open Networks</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">
            <MapPin size={24} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{statistics.hidden_networks || 0}</div>
            <div className="stat-label">Hidden Networks</div>
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="charts-section">
        <div className="chart-container">
          <div className="chart-header">
            <h3>Network Types Distribution</h3>
            <PieChart size={20} />
          </div>
          <div className="chart-content">
            <ResponsiveContainer width="100%" height={300}>
              <RechartsPieChart>
                <Pie
                  data={securityChartData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {securityChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </RechartsPieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="chart-container">
          <div className="chart-header">
            <h3>Signal Strength Analysis</h3>
            <BarChart3 size={20} />
          </div>
          <div className="chart-content">
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={signalChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2a3e" />
                <XAxis 
                  dataKey="ssid" 
                  stroke="#a0a0a0"
                  fontSize={12}
                  angle={-45}
                  textAnchor="end"
                  height={80}
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
                <Bar dataKey="signal" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Networks Table */}
      <div className="networks-section">
        <div className="section-header">
          <h3>Discovered Networks</h3>
          <div className="scan-info">
            {scanStatus.last_scan && (
              <span>
                <Clock size={14} />
                Last scan: {new Date(scanStatus.last_scan).toLocaleString()}
              </span>
            )}
          </div>
        </div>
        
        <div className="networks-table">
          <div className="table-header">
            <div className="col-ssid">SSID</div>
            <div className="col-bssid">BSSID</div>
            <div className="col-signal">Signal</div>
            <div className="col-channel">Channel</div>
            <div className="col-security">Security</div>
            <div className="col-type">Type</div>
            <div className="col-method">Method</div>
          </div>
          
          <div className="table-body">
            {networks.length === 0 ? (
              <div className="no-data">
                <Wifi size={48} />
                <p>No networks discovered yet</p>
                <p>Click "Start Scan" to begin discovery</p>
              </div>
            ) : (
              networks.map((network, index) => (
                <div 
                  key={index} 
                  className="table-row"
                  onClick={() => setSelectedNetwork(network)}
                >
                  <div className="col-ssid">
                    <div className="ssid-info">
                      <Wifi size={16} />
                      <span>{network.ssid || 'Hidden Network'}</span>
                    </div>
                  </div>
                  <div className="col-bssid">{network.bssid || 'Unknown'}</div>
                  <div className="col-signal">
                    <div className="signal-bar">
                      <div 
                        className="signal-fill"
                        style={{ 
                          width: `${network.signal_strength || 0}%`,
                          backgroundColor: getSignalColor(network.signal_strength || 0)
                        }}
                      ></div>
                      <span>{network.signal_strength || 0}%</span>
                    </div>
                  </div>
                  <div className="col-channel">{network.channel || 'N/A'}</div>
                  <div className="col-security">
                    <div 
                      className="security-badge"
                      style={{ backgroundColor: getSecurityColor(network.security) }}
                    >
                      {network.security || 'Unknown'}
                    </div>
                  </div>
                  <div className="col-type">{network.network_type || 'Unknown'}</div>
                  <div className="col-method">{network.method || 'Unknown'}</div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Network Details Modal */}
      {selectedNetwork && (
        <div className="modal-overlay" onClick={() => setSelectedNetwork(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Network Details</h3>
              <button 
                className="modal-close"
                onClick={() => setSelectedNetwork(null)}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="detail-grid">
                <div className="detail-item">
                  <label>SSID</label>
                  <span>{selectedNetwork.ssid || 'Hidden Network'}</span>
                </div>
                <div className="detail-item">
                  <label>BSSID</label>
                  <span>{selectedNetwork.bssid || 'Unknown'}</span>
                </div>
                <div className="detail-item">
                  <label>MAC Address</label>
                  <span>{selectedNetwork.mac_address || 'Unknown'}</span>
                </div>
                <div className="detail-item">
                  <label>Signal Strength</label>
                  <span>{selectedNetwork.signal_strength || 0}%</span>
                </div>
                <div className="detail-item">
                  <label>RSSI</label>
                  <span>{selectedNetwork.rssi || -100} dBm</span>
                </div>
                <div className="detail-item">
                  <label>Channel</label>
                  <span>{selectedNetwork.channel || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Frequency</label>
                  <span>{selectedNetwork.frequency || 'Unknown'} MHz</span>
                </div>
                <div className="detail-item">
                  <label>Security</label>
                  <span>{selectedNetwork.security || 'Unknown'}</span>
                </div>
                <div className="detail-item">
                  <label>Encryption</label>
                  <span>{selectedNetwork.encryption || 'Unknown'}</span>
                </div>
                <div className="detail-item">
                  <label>Authentication</label>
                  <span>{selectedNetwork.auth || 'Unknown'}</span>
                </div>
                <div className="detail-item">
                  <label>Network Type</label>
                  <span>{selectedNetwork.network_type || 'Unknown'}</span>
                </div>
                <div className="detail-item">
                  <label>Detection Method</label>
                  <span>{selectedNetwork.method || 'Unknown'}</span>
                </div>
                <div className="detail-item">
                  <label>First Seen</label>
                  <span>{new Date(selectedNetwork.first_seen).toLocaleString()}</span>
                </div>
                <div className="detail-item">
                  <label>Last Seen</label>
                  <span>{new Date(selectedNetwork.last_seen).toLocaleString()}</span>
                </div>
                {selectedNetwork.radio_type && (
                  <div className="detail-item">
                    <label>Radio Type</label>
                    <span>{selectedNetwork.radio_type}</span>
                  </div>
                )}
                {selectedNetwork.adapter_name && (
                  <div className="detail-item">
                    <label>Adapter Name</label>
                    <span>{selectedNetwork.adapter_name}</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Module1;






