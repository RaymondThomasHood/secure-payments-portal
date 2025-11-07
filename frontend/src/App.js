import React, { useState, useEffect } from 'react';
import axios from 'axios';
import 'bootstrap/dist/css/bootstrap.min.css';
import { BrowserRouter as Router, Route, Routes, Navigate, useNavigate } from 'react-router-dom';
import { jwtDecode } from 'jwt-decode';

function App() {
  const [token, setToken] = useState(null);
  const [message, setMessage] = useState('');
  const [formData, setFormData] = useState({});
  const [role, setRole] = useState(null);
  const [payments, setPayments] = useState([]);
  const [reports, setReports] = useState([]);

  // Handle input changes
  const handleInputChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  // Clear message after 5 seconds
  useEffect(() => {
    if (message) {
      const timer = setTimeout(() => setMessage(''), 5000);
      return () => clearTimeout(timer);
    }
  }, [message]);

  // Wrapper component for routes
  const AppContent = () => {
    const navigate = useNavigate();

    // Handle login with redirect
    const login = async (e) => {
      e.preventDefault();
      try {
        const res = await axios.post('https://localhost:5001/login', formData, {
          headers: { 'Content-Type': 'application/json' }
        });
        setToken(res.data.token);
        const decoded = jwtDecode(res.data.token);
        setRole(decoded.role);
        setMessage('Login successful');

        // Redirect based on role
        if (decoded.role === 'employee') {
          navigate('/employee');
        } else {
          navigate('/customer');
        }
      } catch (err) {
        setMessage(err.response?.data.error || 'Login failed');
      }
    };

    // Handle payment (customer only)
    const makePayment = async (e) => {
      e.preventDefault();
      try {
        const res = await axios.post('https://localhost:5001/payment', formData, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setMessage(res.data.message);
      } catch (err) {
        setMessage(err.response?.data.error || 'Payment error');
      }
    };

    // Handle user creation (employee only)
    const createUser = async (e) => {
      e.preventDefault();
      try {
        const res = await axios.post('https://localhost:5001/employee/create-user', formData, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setMessage(res.data.message);
      } catch (err) {
        setMessage(err.response?.data.error || 'User creation failed');
      }
    };

    // Fetch pending payments (employee only)
    const fetchPayments = async () => {
      try {
        const res = await axios.get('https://localhost:5001/employee/payments', {
          headers: { Authorization: `Bearer ${token}` }
        });
        setPayments(res.data);
      } catch (err) {
        setMessage(err.response?.data.error || 'Failed to fetch payments');
      }
    };

    // Update payment status (employee only)
    const updatePayment = async (id, status) => {
      try {
        const res = await axios.post('https://localhost:5001/employee/payment/update', { id, status }, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setMessage(res.data.message);
        fetchPayments();
      } catch (err) {
        setMessage(err.response?.data.error || 'Update failed');
      }
    };

    // Fetch reports (employee only)
    const fetchReports = async () => {
      try {
        const res = await axios.get('https://localhost:5001/employee/reports', {
          headers: { Authorization: `Bearer ${token}` }
        });
        setReports(res.data);
      } catch (err) {
        setMessage(err.response?.data.error || 'Failed to fetch reports');
      }
    };

    return (
      <div className="container mt-5">
        <h1 className="mb-4">Secure International Payments Portal</h1>
        {message && <div className="alert alert-info">{message}</div>}

        <Routes>
          {/* Login Route */}
          <Route
            path="/login"
            element={
              <form onSubmit={login}>
                <input
                  className="form-control mb-2"
                  name="accountNumber"
                  placeholder="Account Number"
                  onChange={handleInputChange}
                  value={formData.accountNumber || ''}
                  required
                />
                <input
                  className="form-control mb-2"
                  name="password"
                  type="password"
                  placeholder="Password"
                  onChange={handleInputChange}
                  value={formData.password || ''}
                  required
                />
                <button className="btn btn-primary" type="submit">Login</button>
              </form>
            }
          />

          {/* Customer Portal */}
          <Route
            path="/customer"
            element={
              token && role === 'customer' ? (
                <form onSubmit={makePayment}>
                  <input
                    className="form-control mb-2"
                    name="amount"
                    placeholder="Amount (e.g., 100)"
                    type="number"
                    min="1"
                    onChange={handleInputChange}
                    value={formData.amount || ''}
                    required
                  />
                  <select
                    className="form-control mb-2"
                    name="currency"
                    onChange={handleInputChange}
                    value={formData.currency || 'ZAR'}
                    required
                  >
                    <option value="ZAR">ZAR</option>
                    <option value="USD">USD</option>
                    <option value="EUR">EUR</option>
                  </select>
                  <input
                    className="form-control mb-2"
                    name="recipient"
                    placeholder="Recipient Account"
                    onChange={handleInputChange}
                    value={formData.recipient || ''}
                    required
                  />
                  <button className="btn btn-success" type="submit">Pay via SWIFT</button>
                </form>
              ) : (
                <Navigate to="/login" />
              )
            }
          />

          {/* Employee Portal */}
          <Route
            path="/employee"
            element={
              token && role === 'employee' ? (
                <div>
                  <h2>Create User</h2>
                  <form onSubmit={createUser}>
                    <input
                      className="form-control mb-2"
                      name="fullName"
                      placeholder="Full Name"
                      onChange={handleInputChange}
                      value={formData.fullName || ''}
                      required
                    />
                    <input
                      className="form-control mb-2"
                      name="idNumber"
                      placeholder="ID Number (13 digits)"
                      onChange={handleInputChange}
                      value={formData.idNumber || ''}
                      pattern="\d{13}"
                      title="13 digits only"
                      required
                    />
                    <input
                      className="form-control mb-2"
                      name="accountNumber"
                      placeholder="Account Number (10-12 digits)"
                      onChange={handleInputChange}
                      value={formData.accountNumber || ''}
                      pattern="\d{10,12}"
                      title="10-12 digits only"
                      required
                    />
                    <input
                      className="form-control mb-2"
                      name="password"
                      type="password"
                      placeholder="Strong Password"
                      onChange={handleInputChange}
                      value={formData.password || ''}
                      required
                    />
                    <button className="btn btn-primary" type="submit">Create User</button>
                  </form>

                  <h2 className="mt-4">Pending Payments</h2>
                  <button className="btn btn-secondary" onClick={fetchPayments}>Load Payments</button>
                  <ul className="list-group mt-3">
                    {payments.map((payment) => (
                      <li key={payment.id} className="list-group-item">
                        Amount: {payment.amount} {payment.currency} to {payment.recipient}
                        <button
                          className="btn btn-success ml-2"
                          onClick={() => updatePayment(payment.id, 'approved')}
                        >
                          Approve
                        </button>
                        <button
                          className="btn btn-danger ml-2"
                          onClick={() => updatePayment(payment.id, 'rejected')}
                        >
                          Reject
                        </button>
                      </li>
                    ))}
                  </ul>

                  <h2 className="mt-4">Management Reports</h2>
                  <button className="btn btn-info" onClick={fetchReports}>Load Reports</button>
                  <table className="table mt-3">
                    <thead>
                      <tr>
                        <th>Status</th>
                        <th>Count</th>
                        <th>Total Amount</th>
                      </tr>
                    </thead>
                    <tbody>
                      {reports.map((report, index) => (
                        <tr key={index}>
                          <td>{report.status}</td>
                          <td>{report.count}</td>
                          <td>{report.total}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Navigate to="/login" />
              )
            }
          />

          {/* Default Route */}
          <Route path="*" element={<Navigate to="/login" />} />
        </Routes>
      </div>
    );
  };

  return (
    <Router>
      <AppContent />
    </Router>
  );
}

export default App;
