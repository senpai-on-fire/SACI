import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

// Initialize MSW
async function enableMocking() {
  // Check if we should enable mocking
  const ENABLE_MOCK_API = import.meta.env.VITE_ENABLE_MOCK_API === "true";
  
  if (ENABLE_MOCK_API) {
    console.log("🔶 Mock API enabled");
    const { worker } = await import('./mocks/browser')
    // Start the MSW worker with custom options
    return worker.start()
  } else {
    console.log("🔷 Using real API endpoints");
  }
}

// Initialize MSW before rendering the app
enableMocking().then(() => {
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
});
