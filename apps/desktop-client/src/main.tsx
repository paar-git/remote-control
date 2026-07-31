import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import App from './App.js';
import './index.css';

const container = document.getElementById('root');
if (container === null) {
  throw new Error('Missing #root element; index.html is malformed.');
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
