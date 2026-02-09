import CopyButton from './CopyButton';

interface PythonHighlightProps {
  code: string;
}

export default function PythonHighlight({ code }: PythonHighlightProps) {
  const highlightPython = (code: string) => {
    // Python keywords
    const keywords = /\b(def|class|import|from|as|if|elif|else|for|while|return|yield|try|except|finally|with|async|await|lambda|pass|break|continue|raise|assert|del|global|nonlocal|in|is|not|and|or|True|False|None)\b/g;
    
    // Decorators
    const decorators = /(@\w+)/g;
    
    // Strings
    const strings = /(["'`])((?:\\.|(?!\1).)*?)\1/g;
    
    // Comments
    const comments = /(#.*$)/gm;
    
    // Function/class names
    const functionNames = /\b(def|class)\s+(\w+)/g;
    
    // Numbers
    const numbers = /\b(\d+\.?\d*)\b/g;
    
    // Built-in functions
    const builtins = /\b(print|len|range|str|int|float|list|dict|set|tuple|open|input|type|isinstance|enumerate|zip|map|filter|sorted|sum|min|max|abs|all|any)\b/g;
    
    let highlighted = code;
    
    // Apply highlighting in order (most specific first)
    highlighted = highlighted.replace(comments, '<span class="text-gray-500">$1</span>');
    highlighted = highlighted.replace(strings, '<span class="text-green-400">$1$2$1</span>');
    highlighted = highlighted.replace(decorators, '<span class="text-yellow-400">$1</span>');
    highlighted = highlighted.replace(functionNames, '<span class="text-purple-400">$1</span> <span class="text-blue-400">$2</span>');
    highlighted = highlighted.replace(keywords, '<span class="text-pink-400">$1</span>');
    highlighted = highlighted.replace(builtins, '<span class="text-cyan-400">$1</span>');
    highlighted = highlighted.replace(numbers, '<span class="text-orange-400">$1</span>');
    
    return highlighted;
  };

  return (
    <div className="relative group">
      <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
        <CopyButton text={code} />
      </div>
      <pre className="text-xs overflow-x-auto">
        <code 
          className="language-python text-purple-100"
          dangerouslySetInnerHTML={{ __html: highlightPython(code) }}
        />
      </pre>
    </div>
  );
}
