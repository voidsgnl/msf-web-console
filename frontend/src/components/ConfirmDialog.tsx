import { useEffect, useId, useRef, useState } from "react";

type ConfirmDialogProps = {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  cancelLabel?: string;
  onConfirm: () => void | Promise<void>;
  onCancel: () => void;
};

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  cancelLabel = "Cancel",
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const [working, setWorking] = useState(false);
  const cancelButtonRef = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    if (!open) return;
    setWorking(false);
    cancelButtonRef.current?.focus();
  }, [open]);

  if (!open) return null;

  const confirm = async () => {
    if (working) return;
    setWorking(true);
    try {
      await onConfirm();
    } finally {
      setWorking(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm animate-fade-in"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !working) onCancel();
      }}
      onKeyDown={(event) => {
        if (event.key === "Escape" && !working) {
          event.preventDefault();
          event.stopPropagation();
          onCancel();
        }
      }}
    >
      <section
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className="w-full max-w-md overflow-hidden rounded-xl border border-border-strong bg-bg-secondary shadow-pop animate-pop-in"
      >
        <div className="flex items-start gap-3 p-5">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-danger/30 bg-danger/10 text-danger">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
          </span>
          <div className="min-w-0">
            <h2 id={titleId} className="text-sm font-semibold text-gray-100">{title}</h2>
            <p id={descriptionId} className="mt-1.5 whitespace-pre-wrap break-words text-xs leading-5 text-gray-400">
              {description}
            </p>
          </div>
        </div>
        <div className="flex justify-end gap-2 border-t border-border bg-bg-primary/40 px-5 py-3">
          <button
            ref={cancelButtonRef}
            type="button"
            disabled={working}
            onClick={onCancel}
            className="btn"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            disabled={working}
            onClick={() => void confirm()}
            className="btn btn-danger font-semibold"
          >
            {working ? "Please wait…" : confirmLabel}
          </button>
        </div>
      </section>
    </div>
  );
}
