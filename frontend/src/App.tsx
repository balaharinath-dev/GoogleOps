import { useState } from 'react';
import CodebasePane from './components/CodebasePane';
import PipelineStream from './components/PipelineStream';
import HistoryPane from './components/HistoryPane';
import RunDetailsModal from './components/RunDetailsModal';

function App() {
  const [isRunning, setIsRunning] = useState(false);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [modalDetails, setModalDetails] = useState<any>(null);

  const handleRunPipeline = () => {
    setIsRunning(true);
    setSelectedRunId(null);
  };

  const handlePipelineComplete = () => {
    setIsRunning(false);
    setRefreshTrigger(prev => prev + 1); // Trigger history refresh
  };

  const handleSelectRun = async (id: string) => {
    setSelectedRunId(id);
    
    // Fetch run details for modal
    try {
      const res = await fetch(`http://localhost:8001/run/${id}`);
      const data = await res.json();
      setModalDetails(data);
    } catch (error) {
      console.error('Failed to load run details:', error);
    }
  };

  const handleCloseModal = () => {
    setModalDetails(null);
    setSelectedRunId(null);
  };

  return (
    <div className="h-screen bg-[#0a0a0a] text-gray-100 flex overflow-hidden">
      {/* Left Pane - Codebase & History (1/5 width = 20%) */}
      <div className="w-[20%] border-r border-gray-800 flex flex-col">
        <CodebasePane />
        <HistoryPane 
          onSelectRun={handleSelectRun} 
          selectedRunId={selectedRunId}
          refreshTrigger={refreshTrigger}
        />
      </div>

      {/* Middle & Right Panes - Pipeline Stream & Report (4/5 width = 80%, split 2:2) */}
      <div className="flex-1 flex">
        <PipelineStream 
          isRunning={isRunning}
          onRunPipeline={handleRunPipeline}
          onComplete={handlePipelineComplete}
        />
      </div>

      {/* Modal for history details */}
      {modalDetails && (
        <RunDetailsModal 
          details={modalDetails}
          onClose={handleCloseModal}
        />
      )}
    </div>
  );
}

export default App;
