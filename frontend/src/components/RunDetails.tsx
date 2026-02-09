import { CheckCircle, XCircle, Clock, GitCommit, User, Calendar, ExternalLink, Code, Network } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import CopyButton from './CopyButton';

interface RunDetailsProps {
  details: any;
}

export default function RunDetails({ details }: RunDetailsProps) {
  const { run, tests, test_stats, module_stats, test_scripts, final_graph_state } = details;

  const getDecisionBadge = (decision: string) => {
    if (decision === 'DEPLOY') {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-green-900/30 text-green-400 rounded-full text-sm font-medium">
          <CheckCircle className="w-4 h-4" />
          DEPLOY
        </span>
      );
    } else if (decision === 'BLOCK') {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-red-900/30 text-red-400 rounded-full text-sm font-medium">
          <XCircle className="w-4 h-4" />
          BLOCK
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-gray-800 text-gray-400 rounded-full text-sm font-medium">
        <Clock className="w-4 h-4" />
        PENDING
      </span>
    );
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="p-4 bg-gray-800/30 rounded-lg border border-gray-700">
        <div className="flex items-start justify-between mb-3">
          <div className="flex-1">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-200 mb-1">Pipeline Run</h3>
              <CopyButton text={run.run_id} />
            </div>
            <p className="text-xs text-gray-500 font-mono">{run.run_id}</p>
          </div>
          {getDecisionBadge(run.decision)}
        </div>

        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="flex items-center gap-2">
            <GitCommit className="w-3.5 h-3.5 text-gray-500" />
            <span className="text-gray-400">Commit:</span>
            <span className="text-gray-300 font-mono">{run.commit_hash?.slice(0, 8) || 'N/A'}</span>
          </div>
          <div className="flex items-center gap-2">
            <User className="w-3.5 h-3.5 text-gray-500" />
            <span className="text-gray-400">Author:</span>
            <span className="text-gray-300 truncate">{run.commit_author?.split('<')[0].trim() || 'N/A'}</span>
          </div>
          <div className="flex items-center gap-2">
            <Calendar className="w-3.5 h-3.5 text-gray-500" />
            <span className="text-gray-400">Started:</span>
            <span className="text-gray-300">{new Date(run.started_at).toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-2">
            <Clock className="w-3.5 h-3.5 text-gray-500" />
            <span className="text-gray-400">Duration:</span>
            <span className="text-gray-300">
              {run.completed_at 
                ? `${Math.round((new Date(run.completed_at).getTime() - new Date(run.started_at).getTime()) / 1000)}s`
                : 'Running...'}
            </span>
          </div>
        </div>

        {run.commit_message && (
          <div className="mt-3 pt-3 border-t border-gray-700">
            <div className="flex items-start justify-between gap-2">
              <p className="text-xs text-gray-400 leading-relaxed flex-1">{run.commit_message}</p>
              <CopyButton text={run.commit_message} />
            </div>
          </div>
        )}

        {run.jira_story_url && (
          <div className="mt-3 pt-3 border-t border-gray-700">
            <a 
              href={run.jira_story_url} 
              target="_blank" 
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300"
            >
              <ExternalLink className="w-3 h-3" />
              Jira: {run.jira_story_key}
            </a>
          </div>
        )}
      </div>

      {/* Final Graph State */}
      {final_graph_state && (
        <div className="p-4 bg-gray-800/30 rounded-lg border border-gray-700">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-semibold text-gray-400 flex items-center gap-2">
              <Network className="w-3.5 h-3.5" />
              Final Graph State
            </h4>
            <CopyButton text={JSON.stringify(final_graph_state, null, 2)} />
          </div>
          <div className="bg-gray-950/50 rounded-lg overflow-hidden">
            <SyntaxHighlighter
              language="json"
              style={vscDarkPlus}
              customStyle={{
                margin: 0,
                padding: '1rem',
                fontSize: '0.75rem',
                background: 'transparent',
              }}
            >
              {JSON.stringify(final_graph_state, null, 2)}
            </SyntaxHighlighter>
          </div>
        </div>
      )}

      {/* Test Statistics */}
      {test_stats && Object.keys(test_stats).length > 0 && (
        <div className="p-4 bg-gray-800/30 rounded-lg border border-gray-700">
          <h4 className="text-xs font-semibold text-gray-400 mb-3">Test Results</h4>
          <div className="grid grid-cols-3 gap-3">
            {test_stats.PASSED && (
              <div className="p-3 bg-green-900/20 rounded-lg border border-green-800/30">
                <div className="text-2xl font-bold text-green-400">{test_stats.PASSED}</div>
                <div className="text-xs text-green-300">Passed</div>
              </div>
            )}
            {test_stats.FAILED && (
              <div className="p-3 bg-red-900/20 rounded-lg border border-red-800/30">
                <div className="text-2xl font-bold text-red-400">{test_stats.FAILED}</div>
                <div className="text-xs text-red-300">Failed</div>
              </div>
            )}
            {test_stats.ERROR && (
              <div className="p-3 bg-yellow-900/20 rounded-lg border border-yellow-800/30">
                <div className="text-2xl font-bold text-yellow-400">{test_stats.ERROR}</div>
                <div className="text-xs text-yellow-300">Errors</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Module Statistics */}
      {module_stats && module_stats.length > 0 && (
        <div className="p-4 bg-gray-800/30 rounded-lg border border-gray-700">
          <h4 className="text-xs font-semibold text-gray-400 mb-3">Module Coverage</h4>
          <div className="space-y-2">
            {module_stats.map((mod: any, idx: number) => (
              <div key={idx} className="p-3 bg-gray-900/50 rounded">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-gray-300">{mod.module_name}</span>
                  <span className="text-xs text-gray-400">{mod.pass_rate.toFixed(1)}%</span>
                </div>
                <div className="w-full bg-gray-800 rounded-full h-1.5">
                  <div 
                    className="bg-green-500 h-1.5 rounded-full transition-all"
                    style={{ width: `${mod.pass_rate}%` }}
                  />
                </div>
                <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
                  <span>{mod.total_tests} tests</span>
                  <span className="text-green-400">{mod.passed_tests} passed</span>
                  {mod.failed_tests > 0 && (
                    <span className="text-red-400">{mod.failed_tests} failed</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Failed Tests Details */}
      {tests && tests.filter((t: any) => t.status === 'FAILED').length > 0 && (
        <div className="p-4 bg-red-900/10 rounded-lg border border-red-800/30">
          <h4 className="text-xs font-semibold text-red-400 mb-3">Failed Tests</h4>
          <div className="space-y-2">
            {tests.filter((t: any) => t.status === 'FAILED').map((test: any, idx: number) => (
              <details key={idx} className="group">
                <summary className="cursor-pointer p-2 bg-red-900/20 rounded hover:bg-red-900/30 transition-colors">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-red-300 font-mono">{test.test_name}</span>
                    <span className="text-xs text-red-400">{test.test_module}</span>
                  </div>
                </summary>
                {test.error_message && (
                  <div className="mt-2 p-2 bg-red-900/10 rounded relative group/error">
                    <div className="absolute top-2 right-2 opacity-0 group-hover/error:opacity-100 transition-opacity">
                      <CopyButton text={test.error_message} />
                    </div>
                    <pre className="text-xs text-red-300 whitespace-pre-wrap font-mono pr-8">
                      {test.error_message}
                    </pre>
                  </div>
                )}
              </details>
            ))}
          </div>
        </div>
      )}

      {/* Pipeline Summary */}
      {run.pipeline_summary && (
        <div className="p-4 bg-gray-800/20 rounded-lg border border-gray-800 relative group">
          <div className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity">
            <CopyButton text={run.pipeline_summary} />
          </div>
          <h4 className="text-xs font-semibold text-gray-500 mb-3">Pipeline Summary</h4>
          <div className="prose prose-invert prose-sm max-w-none prose-headings:text-gray-400 prose-p:text-gray-500 prose-strong:text-gray-400 prose-code:text-gray-500 prose-pre:bg-gray-950/30 prose-a:text-gray-500 prose-li:text-gray-500">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {run.pipeline_summary}
            </ReactMarkdown>
          </div>
        </div>
      )}

      {/* Test Scripts */}
      {test_scripts && Object.keys(test_scripts).length > 0 && (
        <div className="p-4 bg-gray-800/30 rounded-lg border border-gray-700">
          <h4 className="text-xs font-semibold text-gray-400 mb-3 flex items-center gap-2">
            <Code className="w-3.5 h-3.5" />
            Generated Test Scripts ({Object.keys(test_scripts).length})
          </h4>
          <div className="space-y-3">
            {Object.entries(test_scripts).map(([filename, content]: [string, any]) => (
              <details key={filename} className="group">
                <summary className="cursor-pointer p-3 bg-gray-900/50 border border-gray-700 rounded hover:bg-gray-900/70 transition-colors">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-gray-300 font-mono">{filename}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-500">{content.length} chars</span>
                    </div>
                  </div>
                </summary>
                <div className="mt-2 bg-gray-950/50 rounded-lg overflow-hidden border border-gray-700 relative group/code">
                  <div className="absolute top-2 right-2 z-10 opacity-0 group-hover/code:opacity-100 transition-opacity">
                    <CopyButton text={content} />
                  </div>
                  <SyntaxHighlighter
                    language="python"
                    style={vscDarkPlus}
                    customStyle={{
                      margin: 0,
                      padding: '1rem',
                      fontSize: '0.75rem',
                      background: 'transparent',
                    }}
                  >
                    {content}
                  </SyntaxHighlighter>
                </div>
              </details>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
