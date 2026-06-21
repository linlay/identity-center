import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './app/App';
import { toRouterBasename, uiBaseUrl } from './shared/config/urls';
import './styles/tokens.css';
import './styles/base.css';
import './styles/components.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter basename={toRouterBasename(uiBaseUrl)}>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
