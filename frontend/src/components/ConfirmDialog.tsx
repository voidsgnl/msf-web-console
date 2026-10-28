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
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 p-4"
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
        className="w-full max-w-md overflow-hidden rounded-lg border border-border bg-bg-primary shadow-2xl"
      >
        <div className="border-b border-border px-4 py-3">
          <p className="text-[10px] uppercase tracking-widest text-danger">Confirm action</p>
          <h2 id={titleId} className="mt-1 text-sm font-semibold text-gray-100">{title}</h2>
        </div>
        <div className="p-4">
          <p id={descriptionId} className="whitespace-pre-wrap break-words text-xs leading-5 text-gray-400">
            {description}
          </p>
          <div className="mt-5 flex justify-end gap-2">
            <button
              ref={cancelButtonRef}
              type="button"
              disabled={working}
              onClick={onCancel}
              className="rounded border border-border px-3 py-2 text-xs text-gray-300 hover:bg-bg-tertiary disabled:opacity-50"
            >
              {cancelLabel}
            </button>
            <button
              type="button"
              disabled={working}
              onClick={() => void confirm()}
              className="rounded border border-danger/40 bg-danger/10 px-3 py-2 text-xs font-semibold text-danger hover:bg-danger/20 disabled:opacity-50"
            >
              {working ? "Please wait…" : confirmLabel}
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}
