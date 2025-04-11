import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './globals.css';

// Find the root DOM element
const container = document.getElementById('root');

// Ensure the container element exists before trying to render into it
if (!container) {
  throw new Error('Fatal Error: Root element not found in the DOM.');
}

// Create a root using the React 19 API
const root = createRoot(container);

// Initial render of the App component
root.render(
  // StrictMode helps catch potential problems in an application
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

console.log('React 19 app mounted (TypeScript).');
