import { useState, useEffect } from 'react'
import axios from 'axios'
import { Shield, AlertTriangle, CheckCircle, Activity, Database, RefreshCw } from 'lucide-react'
import FindingsTable from './components/FindingsTable'

// Configure Axios base URL
const API_URL = 'http://127.0.0.1:5000/api';

function App() {
  const [stats, setStats] = useState(null)
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    setError(null)
    try {
      const statsRes = await axios.get(`${API_URL}/stats`)
      setStats(statsRes.data)

      const resultsRes = await axios.get(`${API_URL}/results/latest`)
      setFindings(resultsRes.data.findings || [])

      setLoading(false)
    } catch (err) {
      console.error("Failed to fetch data:", err)
      // If 404, it just means no scan yet
      if (err.response && err.response.status === 404) {
        setFindings([])
        setLoading(false)
      } else {
        setError("backend_connection_error") // Simplified error handling
        setLoading(false)
      }
    }
  }

  const triggerScan = async () => {
    setScanning(true)
    setError(null)
    try {
      await axios.post(`${API_URL}/scan`, { region: 'us-east-1' })
      // Poll for completion
      const interval = setInterval(async () => {
        try {
          const res = await axios.get(`${API_URL}/results/latest`)
          // Check if timestamp is newer or just assume it's the one we wanted
          // For prototype, just clearing interval after first success and updating
          clearInterval(interval)
          fetchData()
          setScanning(false)
        } catch (e) {
          // Keep polling if not ready
        }
      }, 2000)

      // Safety timeout
      setTimeout(() => {
        clearInterval(interval)
        setScanning(false)
      }, 60000)

    } catch (err) {
      setError("Failed to start scan")
      setScanning(false)
    }
  }

  if (loading) return <div className="flex h-screen items-center justify-center bg-gray-900 text-white animate-pulse">Loading Dashboard...</div>

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8 w-full font-sans">
      <header className="flex justify-between items-center mb-10 border-b border-gray-700 pb-6">
        <div className="flex items-center gap-3">
          <Shield className="w-10 h-10 text-blue-500" />
          <div>
            <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-500">
              AntiGravity
            </h1>
            <p className="text-gray-400 text-sm">Cloud Security Scanner</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {stats?.timestamp && (
            <span className="text-gray-500 text-sm">
              Last scan: {new Date(stats.timestamp).toLocaleString()}
            </span>
          )}
          <button
            onClick={triggerScan}
            disabled={scanning}
            className={`px-6 py-2 rounded-lg font-semibold transition-all flex items-center gap-2 ${scanning
              ? 'bg-gray-700 cursor-wait'
              : 'bg-blue-600 hover:bg-blue-700 shadow-lg hover:shadow-blue-500/30'
              }`}
          >
            {scanning ? (
              <><RefreshCw className="w-4 h-4 animate-spin" /> Scanning...</>
            ) : (
              <><Activity className="w-4 h-4" /> Run Scan</>
            )}
          </button>
        </div>
      </header>

      {error === 'backend_connection_error' && (
        <div className="bg-red-900/30 border border-red-500/50 text-red-200 p-6 rounded-xl mb-8 flex items-center gap-4">
          <AlertTriangle className="w-8 h-8 flex-shrink-0" />
          <div>
            <h3 className="font-bold text-lg">Backend API Unavailable</h3>
            <p>Ensure the Flask server is running on port 5000.</p>
            <code className="bg-black/30 px-2 py-1 rounded text-sm mt-2 block w-fit">python -m antigravity.dashboard.app</code>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <StatCard
          title="Compliance Score"
          value={`${stats?.compliance_score || 0}%`}
          icon={<CheckCircle className="text-green-400" />}
          color="green"
        />
        <StatCard
          title="Total Findings"
          value={stats?.total_findings || 0}
          icon={<AlertTriangle className="text-yellow-400" />}
          color="yellow"
        />
        <StatCard
          title="Critical Risks"
          value={stats?.critical_findings || 0}
          icon={<Shield className="text-red-500" />}
          color="red"
        />
        <StatCard
          title="Resources Scanned"
          value={stats?.resources_scanned || 0}
          icon={<Database className="text-blue-400" />}
          color="blue"
        />
      </div>

      <div className="mb-10">
        <FindingsTable findings={findings} />
      </div>
    </div>
  )
}

function StatCard({ title, value, icon, color }) {
  const colors = {
    green: "border-green-500/30 bg-green-500/5",
    yellow: "border-yellow-500/30 bg-yellow-500/5",
    red: "border-red-500/30 bg-red-500/5",
    blue: "border-blue-500/30 bg-blue-500/5"
  }

  return (
    <div className={`p-6 rounded-xl border ${colors[color]} backdrop-blur-sm transition-all hover:scale-[1.02]`}>
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-gray-400 text-sm font-medium tracking-wide uppercase">{title}</h3>
        {icon}
      </div>
      <p className="text-3xl font-bold tracking-tight">{value}</p>
    </div>
  )
}

export default App
