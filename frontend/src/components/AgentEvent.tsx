import { useState } from 'react';
import { ChevronDown, ChevronRight, Bot, Wrench, CheckCircle } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import CopyButton from './CopyButton';

interface AgentEventProps {
  event: {
    type: string;
    data: any;
  };
}

export default function AgentEvent({ event }: AgentEventProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  if (event.type === 'start') {
    return (
      <div className="p-3 bg-gray-900/50 border border-gray-800 rounded-lg">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
          <span className="text-sm text-gray-300">Pipeline Started</span>
        </div>
        <div className="mt-2 text-xs text-gray-500 font-mono">
          Run ID: {event.data.run_id}
        </div>
      </div>
    );
  }

  if (event.type === 'agent_complete') {
    const { agent, output, node } = event.data;
    
    // Extract key information from output
    const renderOutput = () => {
      if (!output) return null;

      // Check if output contains markdown-like content
      const isMarkdown = typeof output === 'string' || 
                        (output.push_analysis || output.code_analysis || output.generated_tests || 
                         output.test_results || output.deployment_decision || output.pipeline_summary);

      return (
        <div className="space-y-3">
          {Object.entries(output).map(([key, value]: [string, any]) => {
            // Skip internal keys
            if (key === 'next_agent' || key === 'messages' || !value) return null;

            const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            
            // Check if value looks like markdown or long text
            const isLongText = typeof value === 'string' && value.length > 100;
            const hasMarkdownSyntax = typeof value === 'string' && 
              (value.includes('##') || value.includes('**') || value.includes('- ') || value.includes('\n\n'));

            return (
              <div key={key} className="space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-gray-400">{displayKey}:</span>
                  {typeof value === 'string' && (
                    <CopyButton text={value} />
                  )}
                </div>
                
                {typeof value === 'string' ? (
                  hasMarkdownSyntax ? (
                    <div className="p-3 bg-gray-950/50 rounded border border-gray-800">
                      <div className="prose prose-invert prose-sm max-w-none prose-headings:text-gray-300 prose-p:text-gray-400 prose-code:text-gray-400">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>
                          {value}
                        </ReactMarkdown>
                      </div>
                    </div>
                  ) : isLongText ? (
                    <div className="p-2 bg-gray-950/50 rounded border border-gray-800">
                      <pre className="text-xs text-gray-400 whitespace-pre-wrap font-mono">
                        {value}
                      </pre>
                    </div>
                  ) : (
                    <div className="text-xs text-gray-300 pl-2">
                      {value}
                    </div>
                  )
                ) : typeof value === 'object' && value !== null ? (
                  Array.isArray(value) ? (
                    <div className="space-y-1">
                      {value.map((item, idx) => (
                        <div key={idx} className="text-xs text-gray-300 pl-2 flex items-center gap-2">
                          <span className="text-gray-600">•</span>
                          {typeof item === 'string' ? item : JSON.stringify(item)}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <details className="group/detail">
                      <summary className="cursor-pointer text-xs text-blue-400 hover:text-blue-300">
                        View details
                      </summary>
                      <div className="mt-2 p-2 bg-gray-950/50 rounded border border-gray-800">
                        <pre className="text-xs text-gray-400 whitespace-pre-wrap font-mono">
                          {JSON.stringify(value, null, 2)}
                        </pre>
                      </div>
                    </details>
                  )
                ) : (
                  <div className="text-xs text-gray-300 pl-2">
                    {String(value)}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      );
    };
    
    return (
      <div className="border border-gray-800 rounded-lg overflow-hidden bg-gray-900/30">
        <div 
          className="p-3 cursor-pointer hover:bg-gray-800/50 transition-colors"
          onClick={() => setIsExpanded(!isExpanded)}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 flex-wrap">
              <Bot className="w-4 h-4 text-blue-400" />
              <span className="inline-block px-2.5 py-1 bg-blue-900/30 text-blue-300 rounded-full text-xs font-medium">
                {agent}
              </span>
              <div className="flex items-center gap-1.5">
                <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                <span className="text-xs text-green-400">Complete</span>
              </div>
            </div>
            {isExpanded ? (
              <ChevronDown className="w-4 h-4 text-gray-500" />
            ) : (
              <ChevronRight className="w-4 h-4 text-gray-500" />
            )}
          </div>
        </div>

        {isExpanded && (
          <div className="p-4 border-t border-gray-800 bg-gray-950/50">
            {renderOutput()}
          </div>
        )}
      </div>
    );
  }

  if (event.type === 'tool_call') {
    const { tool_name, tool_input, tool_output } = event.data;
    
    return (
      <div className="ml-6 border-l-2 border-purple-500/30 pl-3">
        <div className="p-2 bg-purple-900/10 border border-purple-800/30 rounded-lg">
          <div className="flex items-center gap-2 mb-2">
            <Wrench className="w-3.5 h-3.5 text-purple-400" />
            <span className="inline-block px-2 py-0.5 bg-purple-900/30 text-purple-300 rounded-full text-xs font-medium">
              {tool_name}
            </span>
          </div>
          
          {tool_input && (
            <details className="group/tool mb-2">
              <summary className="cursor-pointer text-xs text-gray-400 hover:text-gray-300 flex items-center gap-1">
                <ChevronRight className="w-3 h-3 group-open/tool:rotate-90 transition-transform" />
                Input
              </summary>
              <div className="mt-1 p-2 bg-gray-950/50 rounded text-xs text-gray-400 font-mono">
                {typeof tool_input === 'string' ? tool_input : JSON.stringify(tool_input, null, 2)}
              </div>
            </details>
          )}
          
          {tool_output && (
            <details className="group/tool">
              <summary className="cursor-pointer text-xs text-gray-400 hover:text-gray-300 flex items-center gap-1">
                <ChevronRight className="w-3 h-3 group-open/tool:rotate-90 transition-transform" />
                Output
              </summary>
              <div className="mt-1 p-2 bg-gray-950/50 rounded text-xs text-gray-400 font-mono">
                {typeof tool_output === 'string' ? tool_output : JSON.stringify(tool_output, null, 2)}
              </div>
            </details>
          )}
        </div>
      </div>
    );
  }

  return null;
}
