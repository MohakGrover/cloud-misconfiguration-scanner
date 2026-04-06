import { AlertTriangle, Shield, CheckCircle, XCircle } from 'lucide-react'

export default function FindingsTable({ findings }) {
    if (!findings || findings.length === 0) {
        return (
            <div className="bg-gray-800 rounded-xl p-8 text-center border border-gray-700">
                <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4" />
                <h3 className="text-xl font-bold text-white mb-2">All Clear!</h3>
                <p className="text-gray-400">No security findings detected in the latest scan.</p>
            </div>
        )
    }

    const severityColor = (severity) => {
        switch (severity) {
            case 'CRITICAL': return 'text-red-500 bg-red-500/10 border-red-500/20'
            case 'HIGH': return 'text-orange-500 bg-orange-500/10 border-orange-500/20'
            case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20'
            case 'LOW': return 'text-blue-500 bg-blue-500/10 border-blue-500/20'
            default: return 'text-gray-500 bg-gray-500/10 border-gray-500/20'
        }
    }

    return (
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
            <div className="p-6 border-b border-gray-700">
                <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                    <AlertTriangle className="text-red-400" /> Security Findings
                </h2>
            </div>

            <div className="overflow-x-auto">
                <table className="w-full text-left text-gray-300">
                    <thead className="bg-gray-900/50 uppercase text-xs font-semibold text-gray-500">
                        <tr>
                            <th className="px-6 py-4">Severity</th>
                            <th className="px-6 py-4">Rule Name</th>
                            <th className="px-6 py-4">Resource</th>
                            <th className="px-6 py-4">Status</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-700">
                        {findings.map((finding, idx) => (
                            <tr key={idx} className="hover:bg-gray-700/30 transition-colors">
                                <td className="px-6 py-4">
                                    <span className={`px-3 py-1 rounded-full text-xs font-bold border ${severityColor(finding.severity)}`}>
                                        {finding.severity}
                                    </span>
                                </td>
                                <td className="px-6 py-4 font-medium text-white">
                                    {finding.rule_name}
                                </td>
                                <td className="px-6 py-4 font-mono text-sm text-blue-300">
                                    {finding.resource_id}
                                </td>
                                <td className="px-6 py-4">
                                    <span className="flex items-center gap-1 text-red-400 text-sm">
                                        <XCircle className="w-4 h-4" /> Failed
                                    </span>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    )
}
