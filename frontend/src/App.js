import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Module1 from './pages/Module1';
import Module3 from './pages/Module3';
import './App.css';

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/module1" element={<Module1 />} />
          <Route path="/module3" element={<Module3 />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;






