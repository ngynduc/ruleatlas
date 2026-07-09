import { createRoot } from 'react-dom/client';
import { Root } from './App';
import './styles.css';

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Unable to find #root element.');
}

createRoot(rootElement).render(<Root />);
