import { useState, useEffect, useRef } from 'react';
import { Play, Loader2, Zap } from 'lucide-react';
import AgentEvent from './AgentEvent';
import FinalReport from './FinalReport';

interface PipelineStreamProps {
  isRunning: boolean;
  onRunPipeline: () => void;
  onComplete: (runId: string) => void;
}

interface StreamEvent {
  type: string;
  data: any;
}

export default function PipelineStream({ isRunning, onRunPipeline, onComplete }: PipelineStreamProps) {
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [finalReport, setFinalReport] = useState<any>(null);
  const [currentAgent, setCurrentAgent] = useState<string | null>(null);
  const [currentTool, setCurrentTool] = useState<string | null>(null);
  const eventsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isRunning) {
      runPipeline();
    }
  }, [isRunning]);

  useEffect(() => {
    eventsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events]);

  const runPipeline = async () => {
    setEvents([]);
    setFinalReport(null);
    setCurrentAgent(null);
    setCurrentTool(null);

    try {
      const response = await fetch('http://localhost:8001/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_path: '../codebase', base_ref: 'HEAD~1' })
      });

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (!reader) return;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = JSON.parse(line.slice(6));
            
            if (data.type === 'agent_complete') {
              setEvents(prev => [...prev, data]);
              setCurrentAgent(null);
              setCurrentTool(null);
            } else if (data.type === 'orchestrator') {
              setCurrentAgent(data.data.decision);
              setCurrentTool(null);
            } else if (data.type === 'tool_call') {
              setCurrentTool(data.data.tool_name);
              setEvents(prev => [...prev, data]);
            } else if (data.type === 'final_report') {
              setFinalReport(data.data);
              setCurrentAgent(null);
              setCurrentTool(null);
            } else if (data.type === 'complete') {
              onComplete(data.data.run_id);
            } else if (data.type === 'start') {
              setEvents(prev => [...prev, data]);
            }
          }
        }
      }
    } catch (error) {
      console.error('Pipeline error:', error);
    }
  };

  return (
    <div className="flex-1 flex">
      {/* Middle Pane - Pipeline Stream (50% of remaining = 40% total) */}
      <div className="w-1/2 border-r border-gray-800 flex flex-col">
        <div className="p-4 border-b border-gray-800">
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Pipeline Stream</h2>
        </div>
        
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {events.length === 0 && !currentAgent ? (
            <div className="flex flex-col items-center justify-center h-full text-gray-600">
              <Zap className="w-16 h-16 mb-4 text-gray-700" />
              <p className="text-sm">Click "Run Pipeline" to start</p>
            </div>
          ) : (
            <>
              {currentAgent && (
                <div className="sticky top-0 z-10 p-3 bg-blue-900/20 border border-blue-800/30 rounded-lg backdrop-blur-sm">
                  <div className="flex items-center gap-2 mb-2">
                    <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                    <span className="text-sm text-blue-300 font-medium">Running Agent:</span>
                    <span className="inline-block px-2.5 py-1 bg-blue-900/40 text-blue-200 rounded-full text-xs font-medium">
                      {currentAgent}
                    </span>
                  </div>
                  {currentTool && (
                    <div className="flex items-center gap-2 ml-6">
                      <div className="w-1.5 h-1.5 bg-purple-400 rounded-full animate-pulse"></div>
                      <span className="text-xs text-purple-300">Tool:</span>
                      <span className="inline-block px-2 py-0.5 bg-purple-900/30 text-purple-200 rounded-full text-xs font-medium">
                        {currentTool}
                      </span>
                    </div>
                  )}
                </div>
              )}
              
              {events.map((event, idx) => (
                <AgentEvent key={idx} event={event} />
              ))}
            </>
          )}
          
          <div ref={eventsEndRef} />
        </div>

        <div className="p-4 border-t border-gray-800">
          <button
            onClick={onRunPipeline}
            disabled={isRunning}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 disabled:cursor-not-allowed rounded-lg text-sm font-medium transition-colors"
          >
            {isRunning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Running...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Run Pipeline
              </>
            )}
          </button>
        </div>
      </div>

      {/* Right Pane - Final Report (50% of remaining = 40% total) */}
      <div className="w-1/2 flex flex-col">
        <div className="p-4 border-b border-gray-800">
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Final Report</h2>
        </div>
        
        <div className="flex-1 overflow-y-auto p-4">
          {finalReport ? (
            <FinalReport report={finalReport} />
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-gray-600">
              <Zap className="w-16 h-16 mb-4 text-gray-700" />
              <p className="text-sm">Final report will appear here</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
