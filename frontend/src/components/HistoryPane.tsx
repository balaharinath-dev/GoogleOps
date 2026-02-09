import { useEffect, useState } from 'react';
import { History, CheckCircle, XCircle, Clock, Trash2 } from 'lucide-react';

interface HistoryPaneProps {
  onSelectRun: (runId: string) => void;
  selectedRunId: string | null;
  refreshTrigger?: number; // Add trigger to refresh on pipeline completion
}

interface Run {
  run_id: string;
  decision: string;
  commit_message: string;
  created_at: string;
}

export default function HistoryPane({ onSelectRun, selectedRunId, refreshTrigger }: HistoryPaneProps) {
  const [runs, setRuns] = useState<Run[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchHistory();
  }, []);

  // Refresh when pipeline completes
  useEffect(() => {
    if (refreshTrigger) {
      fetchHistory();
    }
  }, [refreshTrigger]);

  const fetchHistory = async () => {
    try {
      const res = await fetch('http://localhost:8001/history?limit=20');
      const data = await res.json();
      
      console.log('History response:', data);
      
      // Handle structured JSON response
      if (data.runs && Array.isArray(data.runs)) {
        setRuns(data.runs.map((run: any) => ({
          run_id: run.run_id,
          decision: run.decision,
          commit_message: run.commit_message,
          created_at: run.started_at
        })));
        setError(null);
      } else {
        setRuns([]);
      }
    } catch (error) {
      console.error('Failed to fetch history:', error);
      setError('Failed to load history');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (runId: string, e: React.MouseEvent) => {
    e.stopPropagation(); // Prevent triggering the select
    
    if (!confirm('Delete this run?')) return;
    
    try {
      await fetch(`http://localhost:8001/run/${runId}`, {
        method: 'DELETE'
      });
      
      // Remove from local state
      setRuns(prev => prev.filter(run => run.run_id !== runId));
      
      // Clear selection if deleted run was selected
      if (selectedRunId === runId) {
        onSelectRun('');
      }
    } catch (error) {
      console.error('Failed to delete run:', error);
      alert('Failed to delete run');
    }
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <div className="p-4 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <History className="w-3.5 h-3.5 text-gray-500" />
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">History</h2>
        </div>
      </div>
      
      <div className="flex-1 overflow-y-auto p-2">
        {loading ? (
          <div className="p-4 text-center text-xs text-gray-600">Loading...</div>
        ) : error ? (
          <div className="p-4 text-center text-xs text-red-500">{error}</div>
        ) : runs.length === 0 ? (
          <div className="p-4 text-center text-xs text-gray-600">No runs yet</div>
        ) : (
          <div className="space-y-1">
            {runs.map((run) => (
              <div
                key={run.run_id}
                className={`relative group rounded-lg transition-all ${
                  selectedRunId === run.run_id ? 'bg-gray-800/70 border border-gray-700' : 'border border-transparent'
                }`}
              >
                <button
                  onClick={() => onSelectRun(run.run_id)}
                  className="w-full text-left p-3 hover:bg-gray-800/50 rounded-lg transition-all"
                >
                  <div className="flex items-start gap-2 mb-1.5">
                    {run.decision === 'DEPLOY' ? (
                      <CheckCircle className="w-3.5 h-3.5 text-green-500 mt-0.5 flex-shrink-0" />
                    ) : (
                      <XCircle className="w-3.5 h-3.5 text-red-500 mt-0.5 flex-shrink-0" />
                    )}
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-gray-300 line-clamp-2 leading-relaxed">
                        {run.commit_message}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 ml-5">
                    <Clock className="w-3 h-3 text-gray-600" />
                    <span className="text-xs text-gray-600 font-mono">
                      {run.run_id.slice(0, 8)}
                    </span>
                  </div>
                </button>
                
                {/* Delete button - shows on hover */}
                <button
                  onClick={(e) => handleDelete(run.run_id, e)}
                  className="absolute top-2 right-2 p-1.5 bg-red-900/20 hover:bg-red-900/40 text-red-400 rounded opacity-0 group-hover:opacity-100 transition-opacity"
                  title="Delete run"
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
