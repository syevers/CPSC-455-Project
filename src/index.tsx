import React, { Component, ErrorInfo, ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './globals.css';

// Simple React Error Boundary
interface ErrorBoundaryProps {
  children: ReactNode;
}
interface ErrorBoundaryState {
  hasError: boolean;
  error?: Error;
}
class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    // Update state so the next render will show the fallback UI.
    console.error('ErrorBoundary caught an error:', error); // Log the error
    return { hasError: true, error: error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error in App component:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            padding: '20px',
            border: '1px solid red',
            margin: '20px',
            backgroundColor: '#fff',
          }}
        >
          <h1>Something went wrong.</h1>
          <p>There was an error in the chat application. Please try refreshing the page.</p>
          {/* Optionally display error details during development */}
          {process.env.NODE_ENV === 'development' && this.state.error && (
            <pre
              style={{
                marginTop: '10px',
                whiteSpace: 'pre-wrap',
                background: '#fdd',
                padding: '10px',
                border: '1px dashed red',
              }}
            >
              {this.state.error.toString()}
              <br />
              {this.state.error.stack}
            </pre>
          )}
        </div>
      );
    }

    return this.props.children;
  }
}
// ------------------------------------

// Find the root DOM element where the React app will attach
const container = document.getElementById('root');

// Ensure the container element exists before proceeding
if (!container) {
  throw new Error('Fatal Error: Root element not found in the DOM.');
}

// Create a root instance using the React 19 API
const root = createRoot(container);

// Render the application ONCE, inside React.StrictMode and the ErrorBoundary
root.render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);

// Update console log to reflect StrictMode usage in development
console.log('React 19 app mounted (TypeScript - StrictMode Enabled in Dev).');
