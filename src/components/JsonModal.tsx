interface JsonModalProps {
  title: string;
  value: unknown;
  onClose: () => void;
  onCopy: (json: string) => Promise<void> | void;
}

export function JsonModal({ title, value, onClose, onCopy }: JsonModalProps) {
  const json = JSON.stringify(value, null, 2);

  return (
    <div className="modal-backdrop" role="presentation">
      <section aria-label={`${title} JSON`} aria-modal="true" className="json-modal" role="dialog">
        <div className="panel-heading">
          <div>
            <h1>{title}</h1>
            <p>JSON preview</p>
          </div>
          <div className="button-row">
            <button type="button" onClick={() => onCopy(json)}>
              Copy JSON
            </button>
            <button type="button" onClick={onClose}>
              Close
            </button>
          </div>
        </div>
        <pre>{json}</pre>
      </section>
    </div>
  );
}
