import { CheckCircle, XCircle, FileCode } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import CopyButton from './CopyButton';

interface FinalReportProps {
  report: {
    decision: string;
    summary: string;
    test_file_path?: string;
  };
}

export default function FinalReport({ report }: FinalReportProps) {
  const isApproved = report.decision === 'DEPLOY';

  return (
    <div className="space-y-4">
      {/* Decision Badge */}
      <div className={`p-4 rounded-lg border ${
        isApproved 
          ? 'bg-green-900/20 border-green-800/30' 
          : 'bg-red-900/20 border-red-800/30'
      }`}>
        <div className="flex items-center gap-3">
          {isApproved ? (
            <CheckCircle className="w-6 h-6 text-green-400" />
          ) : (
            <XCircle className="w-6 h-6 text-red-400" />
          )}
          <div>
            <div className={`text-lg font-semibold ${
              isApproved ? 'text-green-300' : 'text-red-300'
            }`}>
              {isApproved ? 'APPROVED FOR DEPLOYMENT' : 'DEPLOYMENT BLOCKED'}
            </div>
            <div className="text-xs text-gray-400 mt-1">
              {isApproved ? 'All checks passed' : 'Issues detected'}
            </div>
          </div>
        </div>
      </div>

      {/* Test Scripts */}
      {report.test_file_path && (
        <div className="p-3 bg-gray-900/50 border border-gray-800 rounded-lg">
          <div className="flex items-center gap-2 mb-2">
            <FileCode className="w-4 h-4 text-gray-400" />
            <span className="text-xs text-gray-400">Generated Tests</span>
          </div>
          <div className="inline-block px-2 py-1 bg-purple-900/30 text-purple-300 rounded text-xs font-mono">
            {report.test_file_path.split('/').pop()}
          </div>
        </div>
      )}

      {/* Summary with Markdown */}
      <div className="p-4 bg-gray-900/50 border border-gray-800 rounded-lg relative group">
        <div className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity">
          <CopyButton text={report.summary} />
        </div>
        <div className="prose prose-invert prose-sm max-w-none">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>
            {report.summary}
          </ReactMarkdown>
        </div>
      </div>
    </div>
  );
}
