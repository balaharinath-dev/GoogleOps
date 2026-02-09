import { useEffect, useState } from 'react';
import { GitBranch, GitCommit, User, ChevronDown, ChevronRight } from 'lucide-react';

interface CodebaseStatus {
  repo_path: string;
  branch: string;
  commit: {
    hash_short: string;
    message: string;
    author: string;
    date: string;
  };
}

export default function CodebasePane() {
  const [status, setStatus] = useState<CodebaseStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [isMessageExpanded, setIsMessageExpanded] = useState(false);

  useEffect(() => {
    fetchStatus();
  }, []);

  // No polling - fetch only once on mount

  const fetchStatus = async () => {
    try {
      const res = await fetch('http://localhost:8001/codebase/status');
      const data = await res.json();
      setStatus(data);
    } catch (error) {
      console.error('Failed to fetch codebase status:', error);
    } finally {
      setLoading(false);
    }
  };

  const getTruncatedMessage = (message: string) => {
    const words = message.split(' ');
    if (words.length <= 5) return message;
    return words.slice(0, 5).join(' ') + '...';
  };

  if (loading) {
    return (
      <div className="p-4 border-b border-gray-800">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-800 rounded w-3/4 mb-2"></div>
          <div className="h-3 bg-gray-800 rounded w-1/2"></div>
        </div>
      </div>
    );
  }

  if (!status) return null;

  return (
    <div className="p-4 border-b border-gray-800">
      <h2 className="text-xs font-semibold text-gray-500 mb-4 uppercase tracking-wider flex items-center justify-between">
        <span>Codebase</span>
        <span className="px-2 py-0.5 bg-green-900/30 text-green-400 rounded-full text-xs font-normal normal-case">
          Current
        </span>
      </h2>
      
      {/* Branch */}
      <div className="mb-4">
        <div className="flex items-center gap-2 mb-2">
          <GitBranch className="w-3.5 h-3.5 text-gray-500" />
          <span className="text-xs text-gray-500 font-medium">Branch:</span>
        </div>
        <div className="ml-5">
          <div className="inline-block px-2.5 py-1 bg-gray-800/50 rounded-full text-xs text-gray-300">
            {status.branch}
          </div>
        </div>
      </div>

      {/* Commit ID */}
      <div className="mb-4">
        <div className="flex items-center gap-2 mb-2">
          <GitCommit className="w-3.5 h-3.5 text-gray-500" />
          <span className="text-xs text-gray-500 font-medium">Commit ID:</span>
        </div>
        <div className="ml-5">
          <div className="inline-block px-2.5 py-1 bg-blue-900/20 text-blue-400 rounded text-xs font-mono">
            {status.commit.hash_short}
          </div>
        </div>
      </div>

      {/* User Details */}
      <div className="mb-4">
        <div className="flex items-center gap-2 mb-2">
          <User className="w-3.5 h-3.5 text-gray-500" />
          <span className="text-xs text-gray-500 font-medium">User:</span>
        </div>
        <div className="ml-5">
          <p className="text-xs text-gray-400">{status.commit.author}</p>
        </div>
      </div>

      {/* Commit Message - Collapsible */}
      <div>
        <div 
          className="flex items-center gap-2 mb-2 cursor-pointer hover:text-gray-400 transition-colors"
          onClick={() => setIsMessageExpanded(!isMessageExpanded)}
        >
          {isMessageExpanded ? (
            <ChevronDown className="w-3.5 h-3.5 text-gray-500" />
          ) : (
            <ChevronRight className="w-3.5 h-3.5 text-gray-500" />
          )}
          <span className="text-xs text-gray-500 font-medium">Commit Message:</span>
        </div>
        <div className="ml-5">
          {isMessageExpanded ? (
            <p className="text-xs text-gray-300 leading-relaxed">{status.commit.message}</p>
          ) : (
            <p className="text-xs text-gray-400 leading-relaxed">
              {getTruncatedMessage(status.commit.message)}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
