import React, { useState, useEffect } from 'react';
import { TerminalModalProps, SecurityViolation, SecurityJustification } from '../types/SecurityViolation';

// Terminal-style ASCII animations
const SCANNING_FRAMES = [
  '█▒▒▒▒▒▒▒▒▒',
  '██▒▒▒▒▒▒▒▒',
  '███▒▒▒▒▒▒▒',
  '████▒▒▒▒▒▒',
  '█████▒▒▒▒▒',
  '██████▒▒▒▒',
  '███████▒▒▒',
  '████████▒▒',
  '█████████▒',
  '██████████',
];

const TerminalModal: React.FC<TerminalModalProps> = ({
  violations,
  scanProgress,
  isScanning,
  onFixViolation,
  onRequestOverride,
  onProceed,
  onCancel
}) => {
  const [animationFrame, setAnimationFrame] = useState(0);
  const [selectedViolation, setSelectedViolation] = useState<SecurityViolation | null>(null);
  const [showOverrideForm, setShowOverrideForm] = useState(false);
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);

  // ASCII scanning animation
  useEffect(() => {
    if (isScanning) {
      const interval = setInterval(() => {
        setAnimationFrame((prev) => (prev + 1) % SCANNING_FRAMES.length);
      }, 100);
      return () => clearInterval(interval);
    }
  }, [isScanning]);

  // Add violations to terminal output as they stream in
  useEffect(() => {
    violations.forEach((violation, index) => {
      if (index === terminalOutput.length) {
        const severityColor = getSeverityColor(violation.severity);
        const output = `[${violation.severity}] ${violation.category}: ${violation.title} (${violation.file}:${violation.line})`;
        setTerminalOutput(prev => [...prev, output]);
      }
    });
  }, [violations, terminalOutput.length]);

  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'CRITICAL': return '\x1b[91m'; // Bright red
      case 'HIGH': return '\x1b[31m'; // Red
      case 'MEDIUM': return '\x1b[33m'; // Yellow
      case 'LOW': return '\x1b[36m'; // Cyan
      default: return '\x1b[37m'; // White
    }
  };

  const getSeverityBgColor = (severity: string): string => {
    switch (severity) {
      case 'CRITICAL': return 'bg-red-900 border-red-700';
      case 'HIGH': return 'bg-red-800 border-red-600';
      case 'MEDIUM': return 'bg-yellow-900 border-yellow-700';
      case 'LOW': return 'bg-cyan-900 border-cyan-700';
      default: return 'bg-gray-800 border-gray-600';
    }
  };

  const hasBlockingViolations = violations.some(v => v.severity === 'CRITICAL' || v.severity === 'HIGH');
  const canProceed = !hasBlockingViolations || violations.every(v => v.override);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-90 flex items-center justify-center z-50 font-mono">
      <div className="bg-gray-950 border-2 border-green-500 rounded-lg p-6 max-w-4xl w-full max-h-[80vh] overflow-hidden shadow-2xl">
        
        {/* Terminal Header */}
        <div className="flex items-center justify-between mb-4 border-b border-green-500 pb-2">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-red-500 rounded-full"></div>
            <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
          </div>
          <div className="text-green-400 font-bold text-lg">
            SECURITY CHECKPOINT v1.0
          </div>
          <div className="text-green-400 text-sm">
            {new Date().toISOString()}
          </div>
        </div>

        {/* Scanning Animation */}
        <div className="mb-4">
          <div className="text-green-400 mb-2">
            $ security-scan --phase-transition --owasp-llm-top10
          </div>
          {isScanning && (
            <div className="text-green-300">
              <span className="inline-block">{SCANNING_FRAMES[animationFrame]}</span>
              <span className="ml-2">SCANNING... {Math.round(scanProgress)}%</span>
            </div>
          )}
        </div>

        {/* Terminal Output */}
        <div className="bg-black border border-green-500 rounded p-4 h-64 overflow-y-auto mb-4">
          <div className="text-green-400 text-sm font-mono">
            {terminalOutput.map((output, index) => (
              <div key={index} className="mb-1">
                <span className="text-gray-400">[{index + 1}]</span> {output}
              </div>
            ))}
            {isScanning && (
              <div className="text-green-300 animate-pulse">
                <span className="inline-block">_</span>
              </div>
            )}
          </div>
        </div>

        {/* Violations List */}
        {!isScanning && violations.length > 0 && (
          <div className="mb-4">
            <div className="text-green-400 font-bold mb-2">
              VIOLATIONS DETECTED: {violations.length}
            </div>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {violations.map((violation) => (
                <div
                  key={violation.id}
                  className={`border rounded p-3 cursor-pointer transition-all ${getSeverityBgColor(violation.severity)} ${
                    selectedViolation?.id === violation.id ? 'ring-2 ring-green-400' : ''
                  }`}
                  onClick={() => setSelectedViolation(violation)}
                >
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <div className="text-white font-bold">
                        [{violation.severity}] {violation.category}
                      </div>
                      <div className="text-gray-300 text-sm mt-1">
                        {violation.title}
                      </div>
                      <div className="text-gray-400 text-xs mt-1">
                        {violation.file}:{violation.line}
                      </div>
                    </div>
                    <div className="flex space-x-2">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onFixViolation(violation.id);
                        }}
                        className="bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded text-sm"
                      >
                        FIX
                      </button>
                      {(violation.severity === 'CRITICAL' || violation.severity === 'HIGH') && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedViolation(violation);
                            setShowOverrideForm(true);
                          }}
                          className="bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-sm"
                        >
                          OVERRIDE
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Selected Violation Details */}
        {selectedViolation && !showOverrideForm && (
          <div className="mb-4 bg-gray-900 border border-green-500 rounded p-4">
            <div className="text-green-400 font-bold mb-2">
              VIOLATION DETAILS: {selectedViolation.id}
            </div>
            <div className="text-white space-y-2 text-sm">
              <div><strong>Category:</strong> {selectedViolation.category}</div>
              <div><strong>Description:</strong> {selectedViolation.description}</div>
              <div><strong>Recommendation:</strong> {selectedViolation.recommendation}</div>
              {selectedViolation.cweReference && (
                <div><strong>CWE Reference:</strong> {selectedViolation.cweReference}</div>
              )}
              <div className="bg-black border border-gray-600 rounded p-2 mt-2">
                <div className="text-gray-400 text-xs mb-1">CODE SNIPPET:</div>
                <div className="text-green-300 text-xs">
                  {selectedViolation.codeSnippet}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Override Form */}
        {showOverrideForm && selectedViolation && (
          <div className="mb-4 bg-gray-900 border border-yellow-500 rounded p-4">
            <div className="text-yellow-400 font-bold mb-2">
              SECURITY OVERRIDE JUSTIFICATION
            </div>
            <OverrideForm
              violation={selectedViolation}
              onSubmit={(justification) => {
                onRequestOverride(selectedViolation.id, justification);
                setShowOverrideForm(false);
              }}
              onCancel={() => setShowOverrideForm(false)}
            />
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex justify-between items-center border-t border-green-500 pt-4">
          <button
            onClick={onCancel}
            className="bg-red-600 hover:bg-red-700 text-white px-6 py-2 rounded font-mono"
          >
            CANCEL
          </button>
          <div className="text-green-400 text-sm">
            Status: {hasBlockingViolations ? 'BLOCKED' : 'CLEAR'}
          </div>
          <button
            onClick={onProceed}
            disabled={!canProceed}
            className={`px-6 py-2 rounded font-mono ${
              canProceed
                ? 'bg-green-600 hover:bg-green-700 text-white'
                : 'bg-gray-600 text-gray-400 cursor-not-allowed'
            }`}
          >
            {hasBlockingViolations ? 'PROCEED WITH OVERRIDE' : 'PROCEED'}
          </button>
        </div>
      </div>
    </div>
  );
};

// Override Form Component
const OverrideForm: React.FC<{
  violation: SecurityViolation;
  onSubmit: (justification: SecurityJustification) => void;
  onCancel: () => void;
}> = ({ violation, onSubmit, onCancel }) => {
  const [justification, setJustification] = useState({
    businessReason: '',
    mitigationPlan: '',
    riskAcceptance: '',
    expectedResolution: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 1 week from now
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (justification.businessReason && justification.mitigationPlan && justification.riskAcceptance) {
      onSubmit(justification);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-3">
      <div>
        <label className="text-yellow-400 text-sm block mb-1">Business Reason:</label>
        <textarea
          value={justification.businessReason}
          onChange={(e) => setJustification({...justification, businessReason: e.target.value})}
          className="w-full bg-black border border-gray-600 text-white p-2 rounded text-sm"
          rows={2}
          placeholder="Explain why this violation must be overridden..."
          required
        />
      </div>
      <div>
        <label className="text-yellow-400 text-sm block mb-1">Mitigation Plan:</label>
        <textarea
          value={justification.mitigationPlan}
          onChange={(e) => setJustification({...justification, mitigationPlan: e.target.value})}
          className="w-full bg-black border border-gray-600 text-white p-2 rounded text-sm"
          rows={2}
          placeholder="Describe how you will mitigate this risk..."
          required
        />
      </div>
      <div>
        <label className="text-yellow-400 text-sm block mb-1">Risk Acceptance:</label>
        <textarea
          value={justification.riskAcceptance}
          onChange={(e) => setJustification({...justification, riskAcceptance: e.target.value})}
          className="w-full bg-black border border-gray-600 text-white p-2 rounded text-sm"
          rows={2}
          placeholder="Acknowledge the risks you are accepting..."
          required
        />
      </div>
      <div>
        <label className="text-yellow-400 text-sm block mb-1">Expected Resolution:</label>
        <input
          type="date"
          value={justification.expectedResolution.toISOString().split('T')[0]}
          onChange={(e) => setJustification({...justification, expectedResolution: new Date(e.target.value)})}
          className="w-full bg-black border border-gray-600 text-white p-2 rounded text-sm"
          required
        />
      </div>
      <div className="flex space-x-2">
        <button
          type="submit"
          className="bg-yellow-600 hover:bg-yellow-700 text-white px-4 py-2 rounded text-sm"
        >
          SUBMIT OVERRIDE
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded text-sm"
        >
          CANCEL
        </button>
      </div>
    </form>
  );
};

export default TerminalModal;
