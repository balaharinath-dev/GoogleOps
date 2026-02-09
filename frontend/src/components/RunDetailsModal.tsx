import { X } from 'lucide-react';
import RunDetails from './RunDetails';

interface RunDetailsModalProps {
  details: any;
  onClose: () => void;
}

export default function RunDetailsModal({ details, onClose }: RunDetailsModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="relative w-[90vw] h-[90vh] bg-[#0a0a0a] border border-gray-700 rounded-lg shadow-2xl flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-800">
          <h2 className="text-sm font-semibold text-gray-200">Run Details</h2>
          <button
            onClick={onClose}
            className="p-1.5 hover:bg-gray-800 rounded transition-colors"
          >
            <X className="w-4 h-4 text-gray-400" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          <RunDetails details={details} />
        </div>
      </div>
    </div>
  );
}
