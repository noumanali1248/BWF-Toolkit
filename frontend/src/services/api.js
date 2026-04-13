import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('API Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    console.log(`API Response: ${response.status} ${response.config.url}`);
    return response;
  },
  (error) => {
    console.error('API Response Error:', error);
    if (error.response) {
      // Server responded with error status
      console.error('Error data:', error.response.data);
      console.error('Error status:', error.response.status);
    } else if (error.request) {
      // Request was made but no response received
      console.error('No response received:', error.request);
    } else {
      // Something else happened
      console.error('Error message:', error.message);
    }
    return Promise.reject(error);
  }
);

// API endpoints
export const apiService = {
  // System status
  getSystemStatus: () => api.get('/api/status'),
  
  // Scan operations
  startScan: (duration = 30) => api.post('/api/scan/start', { duration }),
  getScanStatus: () => api.get('/api/scan/status'),
  
  // Network data
  getNetworks: () => api.get('/api/networks'),
  getNetworkDetails: (networkId) => api.get(`/api/networks/${networkId}`),
  
  // Analytics
  getNetworkActivity: () => api.get('/api/network-activity'),
  getThreatTimeline: () => api.get('/api/threat-timeline'),
  
  // Export
  exportData: (format) => api.get(`/api/export/${format}`),
};

export default api;






